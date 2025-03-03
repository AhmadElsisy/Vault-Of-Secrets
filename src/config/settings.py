from configparser import ConfigParser

class Settings:
    def __init__(self):
        self.config = ConfigParser()
        self.load_config()

    def load_config(self):
        self.config.read('config.ini')