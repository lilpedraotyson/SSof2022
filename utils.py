from vulnerabilitiesReport import VulnerabilitiesReport
import copy

class Constant:
	def __init__(self, value):
		self.level = "none"
		self.value = value
	
	def __repr__(self) -> str:
		return 'Constant(%s)' % (self.value)
	
	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		return False

class Variable:
	def __init__(self, name):
		self.name = name 
		self.tainted = False
		self.type = "none"
		self.assigned = False
		self.errors = {}

	def __repr__(self) -> str:
		return 'Variable(%s)' % (self.name)

	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		if variablesBuffer[self.name].type == "source":
			variablesBuffer[self.name].tainted = True
			return True

		if variablesBuffer[self.name].assigned == False:
			variablesBuffer[self.name].tainted = True
			variablesBuffer[self.name].type = "source"
			return True
		
		if pattern["vulnerability"] in variablesBuffer[self.name].errors.keys():
			if len(variablesBuffer[self.name].errors[pattern["vulnerability"]]) != 0:
				variablesBuffer[self.name].tainted = True
				return True

		return variablesBuffer[self.name].tainted

class Break:
	def __init__(self): 
		return
	def __repr__(self) -> str:
		return 'Break()'
	
	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		return False


class Function:
	def __init__(self, name, argsList):
		self.name = name
		self.argsList = argsList 
	
	def __repr__(self) -> str:
		return 'Function(%s, %s)' % (self.name, self.argsList)

	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		#source(?) -> taint
		#source(sink) -> ERRO
		functionIsSource = False
		if self.name in pattern["sources"]:
			functionIsSource = True

		argumentsTainted = []
		for argument in self.argsList:
			#ERROR TYPE source(sink)
			if functionIsSource:
				if isinstance(argument, Variable):
					if variablesBuffer[argument.name].type == "sink":
						VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(argument.name, self.name, []))
				if isinstance(argument, Function):
					if argument.name in pattern["sinks"]:
						VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(argument.name, self.name, []))

			isTaint = argument.isTainted(pattern, variablesBuffer, bodyListStatements)
			if isTaint:
				argumentsTainted.append(argument)
		
		if functionIsSource:
			return True

		if self.name in pattern["sinks"] and len(argumentsTainted) != 0:
			for argument in argumentsTainted:
				iterateAndFindSourceOfError(pattern,variablesBuffer, self.name, argument, [])
			return True
			
		elif len(argumentsTainted) != 0:
			return True
		
		return False
			
class Expression:
	def __init__(self, left, right):
		self.leftSide = left
		self.rightSide = right
	
	def __repr__(self) -> str:
		return 'Expression(%s, %s)' % (self.leftSide, self.rightSide)

	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		leftSideTainted = self.leftSide.isTainted(pattern, variablesBuffer, bodyListStatements)
		rightSideTainted = self.rightSide.isTainted(pattern, variablesBuffer, bodyListStatements)		
		if leftSideTainted or rightSideTainted:
			return True
		return False


class Body:
	#Statements is a list of objects of the class Statement
	def __init__(self, statementsList):
		self.statementsList = statementsList
	
	def __repr__(self) -> str:
		result = ""
		for statement in self.statementsList:
			result += '\n' + str(statement)
		return 'Body(%s)' % (result)

	def isTainted(self, pattern, variablesBuffer, bodyStatementsList):
		count = 0
		for statement in bodyStatementsList:
			count += 1
			if(count >= len(bodyStatementsList)):	
				statement.isTainted(pattern, variablesBuffer, [])
			else:
				statement.isTainted(pattern, variablesBuffer, bodyStatementsList[count:])
			if isinstance(statement, If):
				break

class Statement:
	pass

class Assignment(Statement):
	def __init__(self, variable, expression):
		self.variable = variable
		self.expression = expression
	
	def __repr__(self) -> str:
		return 'Assignment(%s, %s)' % (self.variable, self.expression)

	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		expression = self.expression
		if isinstance(expression, Variable):
			if expression.name == self.variable.name:
				return variablesBuffer[self.variable.name].isTainted(pattern, variablesBuffer)

		isExpressionTainted = self.expression.isTainted(pattern, variablesBuffer, bodyListStatements)
		
		#New assignment, so the previous errors no longer exist, just the new ones that will be calculated
		#BUT if for instance c = c + 1 we need to preserve c errors
		if checkIfVariableIsInExpression(self.variable.name, self.expression) != None: 
			variablesBuffer[self.variable.name].errors = {}
		if isExpressionTainted:
			checkErrors(pattern, variablesBuffer, self.variable.name, self.expression, [])
		
		#New assignment new variables
		#sink = tainted -> ERROR
		#source = ? -> tainted
		#tainted = untainted -> untainted 
		#? = tainted -> tainted
		#? = untainted -> untainted
		if variablesBuffer[self.variable.name].type == "sink" and isExpressionTainted:
			iterateAndFindSourceOfError(pattern, variablesBuffer, self.variable.name, self.expression, [])
			variablesBuffer[self.variable.name].tainted = True
			variablesBuffer[self.variable.name].assigned = True
			return True
		elif variablesBuffer[self.variable.name].type == "source":
			#Only saves path if right side is tainted
			if isExpressionTainted:
				variablesBuffer[self.variable.name].tainted = True
			
			variablesBuffer[self.variable.name].assigned = True
			return True
		elif isExpressionTainted:
			variablesBuffer[self.variable.name].tainted = True
			variablesBuffer[self.variable.name].assigned = True
			return True	
		else:
			variablesBuffer[self.variable.name].assigned = True
			return False
	

class If(Statement):
	def __init__(self, condition, thenBlock, elseBlock):
		self.condition = condition
		self.thenBlock = thenBlock
		self.elseBlock = elseBlock

	def __repr__(self) -> str:
		return 'If(Condition: %s, ThenBlock: %s, ElseBlock: %s)' % (self.condition, self.thenBlock, self.elseBlock)

	def isTainted(self, pattern, variablesBuffer, bodyStatementsList):
		if pattern["implicit"] == "yes":
			taint = self.condition.isTainted(pattern , variablesBuffer, bodyStatementsList)
			if taint:
				errors = {pattern["vulnerability"] : []}
				calculateErrorsOnExpression(pattern, variablesBuffer, self.condition, errors)
				expressionList = self.thenBlock.statementsList + self.elseBlock.statementsList
				for expression in expressionList:
					propagateErrorsOnBodyStatements(pattern, variablesBuffer, expression, errors)

		elseVariablesBuffer = copy.deepcopy(variablesBuffer)
		elsePattern = copy.deepcopy(pattern)
		if len(bodyStatementsList) != 0:
			bodyStatementsListElse = copy.deepcopy(bodyStatementsList)
		else:
			bodyStatementsListElse = []
		bodyStatementsElse = self.elseBlock.statementsList + bodyStatementsListElse

		ifVariablesBuffer = copy.deepcopy(variablesBuffer)
		ifPattern = copy.deepcopy(pattern)
		if len(bodyStatementsList) != 0:
			bodyStatementsListIf = copy.deepcopy(bodyStatementsList)
		else:
			bodyStatementsListIf = []

		bodyStatementsIf = self.thenBlock.statementsList + bodyStatementsListIf

		self.elseBlock.isTainted(elsePattern, elseVariablesBuffer, bodyStatementsElse)
		self.thenBlock.isTainted(ifPattern, ifVariablesBuffer, bodyStatementsIf)

class While(Statement):
	def __init__(self, condition, block):
		self.condition = condition
		self.block = block
	
	def __repr__(self) -> str:
		return 'While(Condition: %s, block: %s)' % (self.condition, self.block)

	def isTainted(self, pattern, variablesBuffer, bodyStatementsList):
		if pattern["implicit"] == "yes":
			taint = self.condition.isTainted(pattern , variablesBuffer, bodyStatementsList)
			if taint:
				errors = {pattern["vulnerability"] : []}
				calculateErrorsOnExpression(pattern, variablesBuffer, self.condition, errors)
				for expression in self.block.statementsList:
					propagateErrorsOnBodyStatements(pattern, variablesBuffer, expression, errors)

		whileVariablesBuffer = copy.deepcopy(variablesBuffer)
		whilePattern = copy.deepcopy(pattern)

		if len(bodyStatementsList) != 0:
			bodyStatementsListWhileBlock = copy.deepcopy(bodyStatementsList)
		else:
			bodyStatementsListWhileBlock = []
		size = len(self.block.statementsList)
		bodyStatementsWhileBlock = (size * self.block.statementsList) + bodyStatementsListWhileBlock

		self.block.isTainted(whilePattern, whileVariablesBuffer, bodyStatementsWhileBlock)

def createErrorObject(sinkName, sourceName, sanitizerFunctionsPassed):
	return {"source": sourceName, "sink": sinkName, "sanitized flows": sanitizerFunctionsPassed}

def createVariableErrorObject(sourceName, sanitizerFunctionsPassed):
	return {"source": sourceName, "sanitized flows": sanitizerFunctionsPassed}

def createErrorObjectFromVariableError(sinkName, variableErrorObject):
	return {"source" : variableErrorObject["source"], "sink": sinkName,
	 		"sanitized flows": variableErrorObject["sanitized flows"]}

def checkErrors(pattern, variablesBuffer, variableName, expressionToIterate, sanitizerFunctionsPassed):
	if isinstance(expressionToIterate, Variable):
		target = variablesBuffer[expressionToIterate.name]
		if target.type == "source":
			if pattern["vulnerability"] not in variablesBuffer[variableName].errors.keys():
				variablesBuffer[variableName].errors[pattern["vulnerability"]] = []
			variablesBuffer[variableName].errors[pattern["vulnerability"]].append(createVariableErrorObject(target.name, sanitizerFunctionsPassed))
		
		if target.tainted == True and target.name != variableName:
			vulnerabilityName = pattern["vulnerability"]
			if vulnerabilityName not in target.errors.keys():
				return
			if vulnerabilityName not in variablesBuffer[variableName].errors.keys():
				variablesBuffer[variableName].errors[vulnerabilityName] = []
			for error in target.errors[vulnerabilityName]:
				errorCopy = copy.deepcopy(error)
				if len(sanitizerFunctionsPassed) != 0:
					if len(errorCopy["sanitized flows"]) == 0:
						errorCopy["sanitized flows"] += sanitizerFunctionsPassed

					elif isinstance(errorCopy["sanitized flows"][0], list):
						for sanitizer in errorCopy["sanitized flows"]:
							if sanitizerFunctionsPassed != sanitizer:
								sanitizer += sanitizerFunctionsPassed
					else:
						if sanitizerFunctionsPassed != errorCopy["sanitized flows"]:
							errorCopy["sanitized flows"] += sanitizerFunctionsPassed
					variablesBuffer[variableName].errors[vulnerabilityName].append(errorCopy)
				else:
					variablesBuffer[variableName].errors[vulnerabilityName].append(errorCopy)
		
		if target.tainted == True and target.name == variableName:
			vulnerabilityName = pattern["vulnerability"]
			if vulnerabilityName not in target.errors.keys():
				target.errors[vulnerabilityName] = []
			for error in target.errors[vulnerabilityName]:
				if len(sanitizerFunctionsPassed) != 0:
					if len(error["sanitized flows"]) == 0:
						error["sanitized flows"] += sanitizerFunctionsPassed

					elif isinstance(error["sanitized flows"][0], list):
						for sanitizer in error["sanitized flows"]:
							if sanitizerFunctionsPassed != sanitizer:
								sanitizer += sanitizerFunctionsPassed
					else:
						if sanitizerFunctionsPassed != error["sanitized flows"]:
							sanitizer += sanitizerFunctionsPassed

	elif isinstance(expressionToIterate, Function):
		if expressionToIterate.name in pattern["sanitizers"]:
			if len(sanitizerFunctionsPassed) != 0:
				sanitizerFunctionsUpdate = copy.deepcopy(sanitizerFunctionsPassed)
				sanitizerFunctionsUpdate.append(expressionToIterate.name)
			else:
				sanitizerFunctionsUpdate = [expressionToIterate.name]
			for argument in expressionToIterate.argsList:
				checkErrors(pattern, variablesBuffer, variableName, argument, sanitizerFunctionsUpdate)
			return

		if expressionToIterate.name in pattern["sources"]:
			if pattern["vulnerability"] not in variablesBuffer[variableName].errors.keys():
				variablesBuffer[variableName].errors[pattern["vulnerability"]] = []
			variablesBuffer[variableName].errors[pattern["vulnerability"]].append(createVariableErrorObject( expressionToIterate.name, sanitizerFunctionsPassed))	
			
		for argument in expressionToIterate.argsList:
			checkErrors(pattern, variablesBuffer, variableName, argument, sanitizerFunctionsPassed)
			

	elif isinstance(expressionToIterate, Expression):
		checkErrors(pattern, variablesBuffer, variableName, expressionToIterate.leftSide, sanitizerFunctionsPassed)
		checkErrors(pattern, variablesBuffer, variableName, expressionToIterate.rightSide, sanitizerFunctionsPassed)


def iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate, sanitizerFunctionsPassed):
	if isinstance(expressionToIterate, Variable):
		target = variablesBuffer[expressionToIterate.name]
		if target.type == "source":
			VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(sinkName, target.name, sanitizerFunctionsPassed))

		for vulnerabilityName in target.errors.keys():
			for error in target.errors[vulnerabilityName]:
				if len(sanitizerFunctionsPassed) != 0:
					errorCopy = copy.deepcopy(error)
					if len(errorCopy["sanitized flows"]) == 0:
						errorCopy["sanitized flows"] += sanitizerFunctionsPassed
					
					elif isinstance(errorCopy["sanitized flows"][0], list):
						for sanitizer in errorCopy["sanitized flows"]:
							if sanitizerFunctionsPassed != sanitizer:
								sanitizer += sanitizerFunctionsPassed
					else:
						if sanitizerFunctionsPassed != errorCopy["sanitized flows"]:
							sanitizer += sanitizerFunctionsPassed
					VulnerabilitiesReport.addError(vulnerabilityName,createErrorObjectFromVariableError(sinkName, errorCopy))
				else:
					VulnerabilitiesReport.addError(vulnerabilityName,createErrorObjectFromVariableError(sinkName, error))

	elif isinstance(expressionToIterate, Function):
		if expressionToIterate.name in pattern["sanitizers"]:
			if len(sanitizerFunctionsPassed) != 0:
				sanitizerFunctionsUpdate = copy.deepcopy(sanitizerFunctionsPassed)
				sanitizerFunctionsUpdate.append(expressionToIterate.name)
			else:
				sanitizerFunctionsUpdate = [expressionToIterate.name]
			for argument in expressionToIterate.argsList:
				iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, argument, sanitizerFunctionsUpdate)
			return

		if expressionToIterate.name in pattern["sources"]:
			VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(sinkName, expressionToIterate.name, sanitizerFunctionsPassed))

		for argument in expressionToIterate.argsList:
			iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, argument, sanitizerFunctionsPassed)
	
	elif isinstance(expressionToIterate, Expression):
		iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate.leftSide, sanitizerFunctionsPassed)
		iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate.rightSide, sanitizerFunctionsPassed)
	

def propagateErrorsOnBodyStatements(pattern, variablesBuffer, expressionToIterate, errors):
	if isinstance(expressionToIterate, Assignment):
		target = variablesBuffer[expressionToIterate.variable.name]
		if pattern["vulnerability"] not in target.errors.keys():
			target.errors[pattern["vulnerability"]] = []
		
		for error in errors[pattern["vulnerability"]]:
			target.errors[pattern["vulnerability"]].append(error) 
			if target.type == "sink":
				VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(target.name, error["source"], error["sanitized flows"]))

	elif isinstance(expressionToIterate, Function):
		if expressionToIterate.name in pattern["sink"]:
			for error in errors[pattern["vulnerability"]]:
				VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(expressionToIterate.name,error["source"], error["sanitized flows"]))

		functionIsSource = False
		if expressionToIterate.name in pattern["sources"]:
			functionIsSource = True
		for argument in expressionToIterate.argsList:
			if functionIsSource:
				if isinstance(argument, Variable):
					if variablesBuffer[argument.name].type == "sink":
						VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(argument.name, expressionToIterate.name, []))
				if isinstance(argument, Function):
					if argument.name in pattern["sinks"]:
						VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(argument.name, expressionToIterate.name, []))

			propagateErrorsOnBodyStatements(pattern, variablesBuffer, argument, errors)
	
	elif isinstance(expressionToIterate, Expression):
		propagateErrorsOnBodyStatements(pattern, variablesBuffer, expressionToIterate.leftSide, errors)
		propagateErrorsOnBodyStatements(pattern, variablesBuffer, expressionToIterate.rightSide, errors)
	
	elif isinstance(expressionToIterate, If):
		for statement in expressionToIterate.thenBlock.statementsList:
			propagateErrorsOnBodyStatements(pattern, variablesBuffer, statement, errors)
		for statement in expressionToIterate.elseBlock.statementsList:
			propagateErrorsOnBodyStatements(pattern, variablesBuffer, statement, errors)
	
	elif isinstance(expressionToIterate, While):
		for statement in expressionToIterate.block.statementsList:
			propagateErrorsOnBodyStatements(pattern, variablesBuffer, statement, errors)
	

def checkIfVariableIsInExpression(variableName, expressionToIterate):
	if isinstance(expressionToIterate, Variable):
		if expressionToIterate.name == variableName:
			return True
	
	if isinstance(expressionToIterate, Function):
		for argument in expressionToIterate.argsList:
			checkIfVariableIsInExpression(variableName, argument)

	if isinstance(expressionToIterate, Expression):
		checkIfVariableIsInExpression(variableName, expressionToIterate.leftSide)
		checkIfVariableIsInExpression(variableName, expressionToIterate.rightSide)


def calculateErrorsOnExpression(pattern, variablesBuffer, expressionTainted, errors):
	if isinstance(expressionTainted, Variable):
		if variablesBuffer[expressionTainted.name].type == "source":
			errors[pattern["vulnerability"]].append(createVariableErrorObject(expressionTainted.name, []))
		if pattern["vulnerability"] in variablesBuffer[expressionTainted.name].errors.keys():
			errors[pattern["vulnerability"]] += variablesBuffer[expressionTainted.name].errors[pattern["vulnerability"]]
			
	
	if isinstance(expressionTainted, Function):
		for argument in expressionTainted.argsList:
			calculateErrorsOnExpression(pattern, variablesBuffer, argument, errors)
	
	if isinstance(expressionTainted, Expression):
		calculateErrorsOnExpression(pattern, variablesBuffer, expressionTainted.leftSide, errors)
		calculateErrorsOnExpression(pattern, variablesBuffer, expressionTainted.rightSide, errors)
