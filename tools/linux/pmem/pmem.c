/*
 * pmem.c - physical memory driver
 * Copyright 2011: Michael Cohen, (scudette@gmail.com)
 *
 * *****************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 * *****************************************************************************
 *
 * This code is also available under Apache 2.0 License
 * Copyright 2011 Michael Cohen (scudette@gmail.com)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *******************************************************************************
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <asm/io.h>
#include <linux/io.h>
#include <asm/uaccess.h>
#include <asm/types.h>

#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/mmzone.h>

static char pmem_devname[32] = "pmem";
#define SUCCESS 0

/* Checks to make sure that the page is valid. For now just checks the
   resource list for "System RAM", which is a very naive approach.
*/
static int is_page_valid(loff_t paddr) {
  struct resource *p = &iomem_resource;

  /* We should really grab the resource lock here but it is not
     exported. The iomem_resource is the root of the resource tree. We
     only care about the top level of the tree here because we just
     need to avoid DMA regions.
  */
  for (p = p->child; p; p = p->sibling) {
    if(p->end > paddr && p->start < paddr) {
      if (!strcmp(p->name, "System RAM")) {
	return 1;
      };
      break;
    };
  };

  return 0;
};

static loff_t pmem_get_size(void) {
  /* The size of memory is the end address of the last
     resource.
  */
  struct resource *p = &iomem_resource;
  struct resource *last_resource = NULL;
  for(p=p->child;p;p=p->sibling) {
    if (!strcmp(p->name, "System RAM")) {
      last_resource=p;
    };
  }
  
  /* This should not happen - something has to be marked as
     allocated.
  */
  if(!last_resource) {
    printk(KERN_WARNING "No valid resources found.");
    
    return -EINVAL;
  } else {
    return last_resource->end;
  };
};


/* Implement seeking behaviour. For whence=2 we need to figure out the
   size of RAM which is the end address of the last "System RAM"
   resource.
*/
static loff_t pmem_llseek(struct file *file, loff_t offset, int whence) {
  switch (whence) {
  case 0: {
    file->f_pos = offset;
    break;
  };

  case 1: {
    file->f_pos += offset;
    break;
  };

  case 2: {
    file->f_pos = pmem_get_size() + offset;
    break;
  };
    
  default:
    return -EINVAL;
  }


  return file->f_pos;
}

/* This function reads as much of the page as possible - it may return
   a short read. If the page is invalid (e.g. the page could not be
   mapped in or its not in a valid memory resource we null pad the
   buffer and log to syslog.   
*/
static ssize_t pmem_read_partial(struct file *file, char *buf, size_t count,
				 loff_t *poff) {
  void *vaddr;
  unsigned long page_offset = *poff % PAGE_SIZE;
  size_t to_read = min(PAGE_SIZE - page_offset, count);
  unsigned long pfn = (unsigned long)(*poff >> PAGE_SHIFT);
  struct page *page;

  /* Refuse to read from invalid pages. */
  if(!is_page_valid(*poff) || !pfn_valid(pfn)) goto error;

  /* Map the page in the the kernel AS and get the address for it. */
  page = pfn_to_page(pfn);
  vaddr = kmap(page);
  if (!vaddr) goto error;
  
  /* Copy the data into the user buffer. */
  if (copy_to_user(buf, vaddr + page_offset, to_read)) {
    goto unmap_error;
  }

  kunmap(page);
  /* Increment the file offset. */
  *poff += to_read;

  return to_read;

 unmap_error:
  kunmap(page);

 error:
  /* Increment the file offset. */
  *poff += to_read;

  /* Error occured we zero pad the result. */
  memset(buf, 0, to_read);
  return to_read;
};

/* Read the buffer requested by copying as much as needed from each
   page. Invalid pages will be replaced with NULLs.
*/
static ssize_t pmem_read(struct file *file, char *buf, size_t count,
			 loff_t *poff) {
  loff_t file_size = pmem_get_size();
  /* How much data is availanle in the entire memory range. */
  size_t available = file_size - *poff;
  size_t remaining = min(count, available);

  if(file_size < *poff)
    return 0;

  /* Just keep going until the full buffer is copied. Due to the null
     padding on error its impossible to fail here.
  */
  while(remaining > 0) {
    remaining -= pmem_read_partial(file, buf, remaining, poff);
  };

  return min(count, available);
}

static unsigned long long zero_page = 0;

static int pmem_vma_fault(struct vm_area_struct *vma,
			  struct vm_fault *vmf)
{
  loff_t offset = vmf->pgoff << PAGE_SHIFT; /* Offset of faulting page */
  unsigned long pfn = (unsigned long)(vmf->pgoff);  /* Faulting page */
  struct page *page;

  /* Refuse to read from invalid pages. Map the zero page instead. */
  if(!is_page_valid(offset) || !pfn_valid(pfn)) {
    page = virt_to_page(zero_page);
  } else { 
    /* Map the real page here. */
    page = pfn_to_page(pfn);
  };

  get_page(page);
  vmf->page = page;
  return 0;
}

static struct vm_operations_struct pmem_vm_ops = {
  .fault = pmem_vma_fault,
};

static int pmem_mmap(struct file *filp, struct vm_area_struct *vma) {
  if(!zero_page) {
    zero_page = get_zeroed_page(GFP_KERNEL);
  };

  /* don't do anything here: The fault handler will fill the holes */
  vma->vm_ops = &pmem_vm_ops;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
  vma->vm_flags |= VM_RESERVED | VM_CAN_NONLINEAR;
#else
  vma->vm_flags |= VM_IO;
#endif

  return 0;
};

/* Set up the module methods. */
static struct file_operations pmem_fops = {
	.owner = THIS_MODULE,
	.llseek = pmem_llseek,
	.read = pmem_read,
	.mmap = pmem_mmap,
};

static struct miscdevice pmem_dev = {
	MISC_DYNAMIC_MINOR,
	pmem_devname,
	&pmem_fops
};


static int __init pmem_init(void)
{
  return misc_register(&pmem_dev);
}

static void __exit pmem_cleanup_module(void)
{
  /* Free the zero page if needed. */
  if(zero_page) {
    free_page(zero_page);
  };
  misc_deregister(&pmem_dev);
}

module_init(pmem_init);
module_exit(pmem_cleanup_module);

MODULE_LICENSE("GPL");
