import utils
from variablesBuffer import VariablesBuffer

def createBodyObject(body):
    statementsList = []
    for statement in body:
        object = None
        if statement["ast_type"] == "Assign":
            object = createAssignmentObject(statement["targets"], statement["value"])
        
        if statement["ast_type"] == "Expr":
            object = createExpressionObject(statement["value"])
        
        if statement["ast_type"] == "If":
            object = createIfStatementObject(statement["body"], statement["orelse"], statement["test"])
        
        if statement["ast_type"] == "While":
            object = createWhileStatementObject(statement["body"], statement["orelse"], statement["test"])
        
        if statement["ast_type"] == "Break":
            object = utils.Break()

        statementsList.append(object)    
    return utils.Body(statementsList) 

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
    
    elif valueObject["ast_type"] == "Name":
        expression = createAstTypeName(valueObject)

    else:
        expression = createExpressionObject(valueObject)

    return utils.Assignment(variable, expression)

def createExpressionObject(valueObject):
    if valueObject["ast_type"] == "Call":
        return createAstTypeCall(valueObject)

    if valueObject["ast_type"] == "BinOp":
        return createAstTypeBinOp(valueObject)

    if valueObject["ast_type"] == "Compare":
        return createAstTypeCompare(valueObject)

    return None

def createIfStatementObject(bodyObject, orElseObject, testObject):
    condition = createExpressionObject(testObject)
    thenBlock = createBodyObject(bodyObject)
    elseBlock = createBodyObject(orElseObject)
    return utils.If(condition, thenBlock, elseBlock)

def createWhileStatementObject(bodyObject, orElseObject, testObject):
    condition = None
    if(testObject["ast_type"] == "Constant"):
        condition = utils.Constant(testObject["value"])
    elif(testObject["ast_type"] == "Name"):
        condition = createAstTypeName(testObject)
    else:
        condition = createExpressionObject(testObject)

    block = createBodyObject(bodyObject)
    if orElseObject != []:
        elseBlock = createBodyObject(orElseObject)
    
    return utils.While(condition,block)

def createAstTypeCall(valueObject):
    functionName = valueObject["func"]["id"]
    arguments = []
    for arg in valueObject["args"]:
        if arg["ast_type"] == "Name":
            arguments.append(createAstTypeName(arg))
        
        if arg["ast_type"] == "Constant":
            arguments.append(utils.Constant(arg["value"]))
        
        if arg["ast_type"] == "BinOp":
            arguments.append(createExpressionObject(arg))
        
        if arg["ast_type"] == "Call":
            arguments.append(createAstTypeCall(arg))
    
    return utils.Function(functionName, arguments)

def createAstTypeName(valueObject):
    if not VariablesBuffer.hasVariable(valueObject["id"]):
        VariablesBuffer.addVariable(valueObject["id"])

    return VariablesBuffer.getVariableObject(valueObject["id"])


def createAstTypeBinOp(object):
    rightSide = object["right"]
    leftSide = object["left"]
    leftResult = None
    if leftSide["ast_type"] == "BinOp":
        leftResult = createAstTypeBinOp(leftSide)

    if leftSide["ast_type"] == "Name":
        leftResult = createAstTypeName(leftSide)

    if leftSide["ast_type"] == "Call":
        leftResult = createAstTypeCall(leftSide)
    

    righResult = None
    if rightSide["ast_type"] == "Constant":
        righResult = utils.Constant(rightSide["value"])

    if rightSide["ast_type"] == "Name":
        righResult = createAstTypeName(rightSide)

    if rightSide["ast_type"] == "Call":
        righResult = createAstTypeCall(rightSide)

    return utils.Expression(leftResult, righResult)

def createAstTypeCompare(object):
    comparators = object["comparators"]
    leftSide = object["left"]
    leftResult = None
    if leftSide["ast_type"] == "BinOp":
        leftResult = createAstTypeBinOp(leftSide)
    if leftSide["ast_type"] == "Name":
        leftResult = createAstTypeName(leftSide)
    
    righResult = None
    if len(comparators) == 1:
        comparator = comparators[0]
        if comparator["ast_type"] == "Constant":
            righResult = utils.Constant(comparator["value"])

        if comparator["ast_type"] == "Name":
            righResult = createAstTypeName(comparator)

    else:
        auxRightResult =  []
        for comparator in comparators:
            comparatorObject = None
            if comparator["ast_type"] == "Constant":
                comparatorObject = utils.Constant(comparator["value"])

            if comparator["ast_type"] == "Name":
                comparatorObject = createAstTypeName(comparator)
            
            auxRightResult.append(comparatorObject)
        
        righResult = createExpressionRecursevily(auxRightResult)

    return utils.Expression(leftResult, righResult)


def createExpressionRecursevily(variablesList):
    if len(variablesList) == 1:
        return variablesList.pop()
    else:
        return utils.Expression(variablesList.pop(0), createExpressionRecursevily(variablesList))
    