#Checkov custom policy "TAG_ACCESS Public"
#v1.0

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories
from lark import Token

class PublicAccessTAG(BaseResourceCheck):
    def __init__(self):
        name = "TAG Public Access "
        id = "IT1_TAG_Public_Access"
        supported_resources = ['aws_instance']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        
        if 'associate_public_ip_address' in conf.keys():
            if conf['associate_public_ip_address'][0] :
                txt = (conf['tags'][0])
                if 'Accessibility' in txt :
                    Tag_Access = txt.find('Accessibility') 
                    Tag_Access = (conf['tags'][0][Tag_Access:-1])
                    last_txt = Tag_Access.find(',')
                    Tag_Access = (Tag_Access[0:last_txt])

                    if 'public' in Tag_Access.lower() :
                        print ("Have Public IP , TAG Ok")
                        return CheckResult.PASSED
                    else :
                        print ("Have Public IP , TAG Ok no Public in tag") 
                        return CheckResult.FAILED
                        
                else :
                    print ("Have Public IP , No tag")
                    return CheckResult.FAILED
                    
            else :  
                print ("No Public IP ")
                return CheckResult.PASSED  
                      

        else :  
            print ("No Public IP ") 
            return CheckResult.PASSED 
             
                    
check = PublicAccessTAG()