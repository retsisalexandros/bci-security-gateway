import time
import random

COMMANDS = ["idle", "select_A", "select_B", "move_left", "move_right", "confirm"]


class CommandGenerator:
    def __init__(self):
        self._current = "idle"
        self._index = 0
        self._next_change = time.time() + random.uniform(2, 5)

    def current_command(self) -> str:
        now = time.time()
        if now >= self._next_change:
            self._index = (self._index + 1) % len(COMMANDS)
            self._current = COMMANDS[self._index]
            self._next_change = now + random.uniform(2, 5)
        return self._current
