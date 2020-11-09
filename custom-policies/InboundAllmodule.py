#Checkov custom policy "Inbound Security groups require restricted access"
#v1.0

from checkov.terraform.checks.module.base_module_check import BaseModuleCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from lark import Token


class SGInbound(BaseModuleCheck):
    def __init__(self):
        name = "Inbound Security groups require restricted access"
        id = "IT1_AWS_Inbound"
        supported_resources = ['module']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_module_conf(self, conf):
        print(str(conf))
        # if 'ingress' in conf.keys(): #conf.keys() will return the array dictionary of ingress
        #     if 'to_port' in conf['ingress'][0].keys(): #check if ingress contain to_port
        #         if 'from_port' in conf['ingress'][0].keys():   #check if ingress contain to_port
        #             check = True #If one of the rule is not meet the requirement, return checkov failed.
        #             for i in range(len(conf['ingress'])):
        #                 if conf['ingress'][i]['cidr_blocks'][0][0] == '0.0.0.0/0' :
        #                     if (conf['ingress'][i]['from_port'][0] == 80 and conf['ingress'][i]['to_port'][0] == 80) or (conf['ingress'][i]['from_port'][0] == 443 and conf['ingress'][i]['to_port'][0] == 443): 
        #                         print('Ingress description "'+conf['ingress'][i]['description'][0]+'" is OK')    
        #                     else :
        #                         check = False
        #                         print('Ingress description "'+conf['ingress'][i]['description'][0]+'" is not meet the requirement')       
        #                 else :
        #                     print('Ingress description "'+conf['ingress'][i]['description'][0]+'" is OK')    
        #             if check :
        #                 return CheckResult.PASSED
        #             else :
        #                 return CheckResult.FAILED
check = SGInbound()