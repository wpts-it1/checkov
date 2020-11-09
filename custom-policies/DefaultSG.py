from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class DefaultSG(BaseResourceCheck):
    def __init__(self):
        name = "Ensure the default security group of every VPC are not used"
        id = "IT1_AWS_DefaultSG"
        supported_resources = ['aws_default_security_group']
        # CheckCategories are defined in models/enums.py
        # https://github.com/bridgecrewio/checkov/blob/master/checkov/common/models/enums.py
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self,conf):
        if 'vpc_id' in conf.keys():
            return CheckResult.FAILED 
        return CheckResult.FAILED

scanner = DefaultSG()