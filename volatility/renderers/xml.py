from volatility import debug
from volatility.renderers.basic import Renderer

__author__ = "simocarina"

try:
	from lxml.etree import ElementTree
	can_parse_xml_files = True
except ImportError:
	can_parse_xml_files = False

class XMLRenderer(Renderer):
	def __init__(self, renderers_func,config):
		if not can_parse_xml_files:
			debug.error("You do not have the required libraries for xml files\nYou have to install lxml")
		self._config = config
		self._tree = ElementTree.parse('xml_renderer.xml')
		self._root = tree.getroot()

	def tags(self):
		output = []
		for column in self._columns:
			output.append((column.name))
		return output

	def _append_element(self, field_name, data, node=self._root.tag):
		if(node==self._root.tag):
			self._root.append(ElementTree.Element(field,attrib={text:data}))
		else:
			for field in root.iter(node):
				field.append(ElementTree.Element(field,attrib={text:data}))
		self._tree.write('xml_renderer.xml')

	def _modify_element(self, data, node=self._root.tag, action = "replace"):

		if(node==self._root.tag):
			if(action=="replace"):
				self._root.text = data
			elif(action=="append"):
				self._root.text = data
		else:
			for field in root.iter(node):
				if(action=="replace"):
					field.text = data
				elif(action=="append"):
					field.text += data
	self._tree('xml_renderer.xml')

	def render(self,outfd,grid):
		if not self._config.OUTPUT_FILE:
            debug.error("Please specify a valid output file using --output-file")
