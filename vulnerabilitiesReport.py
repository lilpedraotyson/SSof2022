class VulnerabilitiesReport:
    errors = {}

    def setup(patterns):
        for pattern in patterns:
            VulnerabilitiesReport.errors[pattern["vulnerability"]] = []


    def addError(vulnerabilityName, object):
        VulnerabilitiesReport.errors[vulnerabilityName].append(object)
    
    

        