import utils
from variablesBuffer import VariablesBuffer

def createAssignmentObject(targets, valueObject):
    variable = None
    for target in targets:
        if target["ast_type"] == "Name":
            if not VariablesBuffer.hasVariable(target["id"]):
                VariablesBuffer.addVariable(target["id"])
            variable = VariablesBuffer.getVariableObject(target["id"])
                

    expression = None
    if valueObject["ast_type"] == "Constant":
        expression = utils.Constant(valueObject["value"])
    
    if valueObject["ast_type"] == "Call":
        expression = createAstTypeCall(valueObject)

    return utils.Assignment(variable, expression)

def createExpressionObject(valueObject):
    if valueObject["ast_type"] == "Call":
        return createAstTypeCall(valueObject)
    
    return None


def createAstTypeCall(valueObject):
    functionName = valueObject["func"]["id"]
    arguments = []
    for arg in valueObject["args"]:
        if arg["ast_type"] == "Name":
            if not VariablesBuffer.hasVariable(arg["id"]):
                VariablesBuffer.addVariable(arg["id"])
            arguments.append(VariablesBuffer.getVariableObject(arg["id"]))
    
    return utils.Function(functionName, arguments)