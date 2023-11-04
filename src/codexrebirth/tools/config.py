import jsonschema
import json
import os


def validate_config(config):
    schema = {
        "type": "object",
        "properties": {
            "rootfs_path": {"type": "string"},
            "log_plain": {"type": "boolean"},
            "debug_level": {"type": "integer"},
            "openai_key": {"type": "string"},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 10000},
            "similarity_factor": {"type": "number", "minimum": 0.3, "maximum": 1},
            "symbolic_check": {"type": "boolean"},
        },
        "required": [
            "rootfs_path",
            "log_plain",
            "debug_level",
            "openai_key",
            "timeout",
            "similarity_factor",
            "symbolic_check",
        ],
    }

    jsonschema.validate(config, schema)


def load_config(config_path):
    config = json.load(open(config_path, "r"))
    validate_config(config)
    return config
