from lark import Token

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class RDSBackupTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS has backup tag"
        id = "IT1_AWS_2020"
        supported_resources = ['aws_db_instance']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'tags' in conf.keys():
            environment_tag = Token("IDENTIFIER", "backup-plan")
            if environment_tag in conf['tags'][0].keys():
                if (conf['tags'][0][environment_tag] == "nprd" or conf['tags'][0][environment_tag] == "prd"):
                    return CheckResult.PASSED
        return CheckResult.FAILED


scanner = RDSBackupTag()