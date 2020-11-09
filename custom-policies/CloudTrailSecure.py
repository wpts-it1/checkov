from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class CloudTrailSecure(BaseResourceCheck):
    def __init__(self):
        name = "Ensure CloudTrail trails are integrated with CloudWatch Logs"
        id = "IT1_AWS_CIS_24"
        supported_resources = ['aws_cloudtrail']
        # CheckCategories are defined in models/enums.py
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'cloud_watch_logs_group_arn' in conf.keys():
            return CheckResult.PASSED
        return CheckResult.FAILED

scanner = CloudTrailSecure()