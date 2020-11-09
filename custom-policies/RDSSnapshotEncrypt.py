#Checkov custom policy "Encryption mandatory for RDS snapshots"
#v1.0

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from lark import Token

class RDSSnapshotEncrypt(BaseResourceCheck):
    def __init__(self):
        name = "Encryption mandatory for RDS snapshots"
        id = "IT1_AWS_RDS_Snapshot_Encrypt"
        supported_resources = ['aws_db_snapshot']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'encrypted' in conf.keys(): #conf.keys() will return the array dictionary
            if (conf['encrypted'][0]) and isinstance(conf['encrypted'][0], bool):
                return CheckResult.PASSED
            else :
                return CheckResult.FAILED
        else :
            return CheckResult.FAILED

check = RDSSnapshotEncrypt()