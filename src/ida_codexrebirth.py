from codexrebirth import CodexRebirth
import os

CONFIG_FILE_NAME = "codexrebirth_config.json"


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    print("CodexRebirth: Loading IDA Plugin...")
    config_path = os.path.join(os.path.dirname(__file__), CONFIG_FILE_NAME)
    return CodexRebirth(config_path)
