#!/bin/python
#    This file is part of recover-evtx.
#
#   Copyright 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from progressbar import Bar, ETA, ProgressBar


class Progress(object):
    """
    An interface to things that track the progress of a long running task.
    """
    def __init__(self, max_):
        super(Progress, self).__init__()
        self._max = max_
        self._current = 0

    def set_current(self, current):
        """
        Set the number of steps that this task has completed.

        @type current: int
        """
        self._current = current

    def set_complete(self):
        """
        Convenience method to set the task as having completed all steps.
        """
        self._current = self._max


class NullProgress(Progress):
    """
    A Progress class that ignores any updates.
    """
    def __init__(self, max_):
        super(NullProgress, self).__init__(max_)

    def set_current(self, current):
        pass


class ProgressBarProgress(Progress):
    def __init__(self, max_):
        super(ProgressBarProgress, self).__init__(max_)

        widgets = ["Progress: ",
                   Bar(marker="=", left="[", right="]"), " ",
                   ETA(), " ", ]
        self._pbar = ProgressBar(widgets=widgets, maxval=self._max)
        self._has_notified_started = False

    def set_current(self, current):
        if not self._has_notified_started:
            self._pbar.start()
            self._has_notified_started = True

        self._pbar.update(current)

    def set_complete(self):
        self._pbar.finish()
