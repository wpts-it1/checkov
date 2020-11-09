#Checkov custom policy "CloudFront must be configured securely"
#v1.0


from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from lark import Token

class CloudFrontSecure(BaseResourceCheck):
    def __init__(self):
        name = "CloudFront must be configured securely"
        id = "IT1_AWS_CloudFront"
        supported_resources = ['aws_cloudfront_distribution']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'viewer_certificate' in conf.keys():
            if 'minimum_protocol_version' in conf['viewer_certificate'][0] :
                if 'TLSv1.2' in conf['viewer_certificate'][0]['minimum_protocol_version'][0] :
                    return CheckResult.PASSED
                else :
                    return CheckResult.FAILED
                    
check = CloudFrontSecure()