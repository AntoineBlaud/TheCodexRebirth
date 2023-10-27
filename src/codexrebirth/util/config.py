import jsonschema


def validate_config(config):
    schema = {
        "type": "object",
        "properties": {
            "rootfs_path": {"type": "string"},
            "log_plain": {"type": "boolean"},
            "debug_level": {"type": "integer"},
            "openai_key": {"type": "string"},
            
        },
        "required": [
            "rootfs_path",
            "log_plain",
            "debug_level",
            "openai_key",
        ]
    }

   
    jsonschema.validate(config, schema)
       