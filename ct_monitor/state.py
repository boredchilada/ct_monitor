import json
import os
import logging
from typing import Dict

class StateManager:
    def __init__(self, state_file: str):
        self.state_file = state_file
        self.log = logging.getLogger(__name__)

    def load_state(self) -> Dict:
        """Loads the last known tree size for each log from a file."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                self.log.error(f"Error loading state file {self.state_file}: {e}")
                return {}
        return {}

    def save_state(self, state: Dict):
        """Saves the current tree sizes to a file atomically."""
        temp_file = f"{self.state_file}.tmp"
        try:
            with open(temp_file, 'w') as f:
                json.dump(state, f, indent=4)
            os.replace(temp_file, self.state_file)
        except IOError as e:
            self.log.error(f"Error saving state file {self.state_file}: {e}")