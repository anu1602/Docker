from grpc.tools.protoc import main as _protoc
from glob import glob
import os
from os.path import dirname as DIRNAME

os.chdir("/project/supply_chain/sc_rest_api/protogen")
Current_directory = "/project/supply_chain/sc_rest_api/protogen"
Target_directory = "/project/supply_chain/sc_rest_api/protogen"
_protoc([__file__, "-I=%s" % Current_directory, "--python_out=%s" % Target_directory] + glob("%s/*.proto" % Current_directory))
