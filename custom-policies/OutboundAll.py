#Checkov custom policy "Outbound Security groups require restricted access"
#v1.0

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from lark import Token

class SGOutbound(BaseResourceCheck):
    def __init__(self):
        name = "Outbound Security groups require restricted access"
        id = "IT1_AWS_Outbound"
        supported_resources = ['aws_security_group']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if 'egress' in conf.keys(): #conf.keys() will return the array dictionary of egress
            if 'to_port' in conf['egress'][0].keys(): #check if egress contain to_port
                if 'from_port' in conf['egress'][0].keys():   #check if egress contain to_port
                    check = True #If one of the rule is not meet the requirement, return checkov failed.
                    for i in range(len(conf['egress'])):
                        if conf['egress'][i]['cidr_blocks'][0][0] == '0.0.0.0/0' :
                            if (conf['egress'][i]['from_port'][0] == 80 and conf['egress'][i]['to_port'][0] == 80) or (conf['egress'][i]['from_port'][0] == 443 and conf['egress'][i]['to_port'][0] == 443): 
                                print('Egress description "'+conf['egress'][i]['description'][0]+'" is OK')    
                            else :
                                check = False
                                print('Egress description "'+conf['egress'][i]['description'][0]+'" is not meet the requirement')       
                        else :
                            print('Egress description "'+conf['egress'][i]['description'][0]+'" is OK')    
                    if check :
                        return CheckResult.PASSED
                    else :
                        return CheckResult.FAILED
check = SGOutbound()