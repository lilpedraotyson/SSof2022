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
		self.variablesThatNotTaint = []

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
						print("ADDING SPECIAL ERROR sink: {} source: {}".format(argument.name, self.name))
						VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(argument.name, self.name, []))
				if isinstance(argument, Function):
					if argument.name in pattern["sinks"]:
						print("ADDING SPECIAL ERROR sink: {} source: {}".format(argument.name, self.name))
						VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(argument.name, self.name, []))

			isTaint = argument.isTainted(pattern, variablesBuffer, bodyListStatements)
			if isTaint:
				argumentsTainted.append(argument)
		
		if functionIsSource:
			return True

		if self.name in pattern["sinks"] and len(argumentsTainted) != 0:
			for argument in argumentsTainted:
				print("FINDING ERROR sink: {} expression: {}".format(self.name, argument))
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
		rightRideTainted = self.rightSide.isTainted(pattern, variablesBuffer, bodyListStatements)
		if leftSideTainted or rightRideTainted:
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
			print("Running:", statement)
			count += 1
			if(count >= len(bodyStatementsList)):	
				statement.isTainted(pattern, variablesBuffer, [])
			else:
				statement.isTainted(pattern, variablesBuffer, bodyStatementsList[count:])

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

		#isVariableTainted = variablesBuffer[self.variable.name].isTainted(pattern, variablesBuffer)
		isExpressionTainted = self.expression.isTainted(pattern, variablesBuffer, bodyListStatements)
		
		#New assignment, so the previous errors no longer exist, just the new ones that will be calculated
		#BUT if for instance c = c + 1 we need to preserve c errors
		if checkIfVariableIsInExpression(self.variable.name, self.expression) != None: 
			variablesBuffer[self.variable.name].errors = {}
		if isExpressionTainted:
			checkErrors(pattern, variablesBuffer, self.variable.name, self.expression, [])
			print("Variable: {} -> errors: {}".format(self.variable.name, variablesBuffer[self.variable.name].errors))
			print("Entering on updateErrorsOnRelatedVariables")
			updateErrorsOnRelatedVariables(pattern, variablesBuffer, self.variable.name)
		else:
			print("Expression NOT TAINTED")
			print("Variable: {} -> errors: {}".format(self.variable.name, variablesBuffer[self.variable.name].errors))
		
		#New assignment new variables
		variablesBuffer[self.variable.name].variablesThatNotTaint = []
		populateVariablesThatNotTaint(pattern, variablesBuffer,self.variable.name, self.expression, []) #Body List Statements not needed
		print("Variable: {} -> variablesThatNotTaint: {}".format(self.variable.name, variablesBuffer[self.variable.name].variablesThatNotTaint))
		#sink = tainted -> !!!ITERATE on path of expressionTainted AND FIND THE SOURCES
							#ASSOCIATED and save in a global variable !!! TODO
		#source = ? -> tainted
		#tainted = untainted -> untainted ?????? -> CHECK with someone later
		#? = tainted -> tainted
		#? = untainted -> untainted
		if variablesBuffer[self.variable.name].type == "sink" and isExpressionTainted:
			#print("ERROU")
			print("FINDING ERROR sink: {} expression: {}".format(self.variable.name, self.expression))
			iterateAndFindSourceOfError(pattern, variablesBuffer, self.variable.name, self.expression, [])
			variablesBuffer[self.variable.name].tainted = True
			#variablesBuffer[self.variable.name].path += [self.expression]
			variablesBuffer[self.variable.name].assigned = True
			return True
		elif variablesBuffer[self.variable.name].type == "source":
			#Only saves path if right side is tainted
			if isExpressionTainted:
				variablesBuffer[self.variable.name].tainted = True
				#variablesBuffer[self.variable.name].path += [self.expression]
			
			variablesBuffer[self.variable.name].assigned = True
			return True
		elif isExpressionTainted:
			variablesBuffer[self.variable.name].tainted = True
			#variablesBuffer[self.variable.name].path += [self.expression]
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
		#check if need to evaluate condition (implicit flow == true)
		#self.condition.isTainted()
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
		#check if need to evaluate condition (implicit flow == true)
		#self.condition.isTainted()
		#print("Entrei")
		whileVariablesBuffer = copy.deepcopy(variablesBuffer)
		whilePattern = copy.deepcopy(pattern)
		#print("BodyStatementsList: ",bodyStatementsList)
		if len(bodyStatementsList) != 0:
			bodyStatementsListWhileBlock = copy.deepcopy(bodyStatementsList)
		else:
			bodyStatementsListWhileBlock = []
		bodyStatementsWhileBlock = self.block.statementsList + bodyStatementsListWhileBlock
		#print("BodyWhileBlock:" , bodyStatementsWhileBlock)

		self.block.isTainted(whilePattern, whileVariablesBuffer, bodyStatementsWhileBlock)




def createErrorObject(sinkName, sourceName, sanitizerFunctionsPassed):
	return {"source": sourceName, "sink": sinkName, "sanitized flows": sanitizerFunctionsPassed}

def createVariableErrorObject(sourceName, sanitizerFunctionsPassed):
	return {"source": sourceName, "sanitized flows": sanitizerFunctionsPassed}

def createErrorObjectFromVariableError(sinkName, variableErrorObject):
	return {"source" : variableErrorObject["source"], "sink": sinkName,
	 		"sanitized flows": variableErrorObject["sanitized flows"]}

def checkErrors(pattern, variablesBuffer, variableName, expressionToIterate, sanitizerFunctionsPassed):
	print("expression on checkErrors: ", expressionToIterate)
	if isinstance(expressionToIterate, Variable):
		#print("Entrei")
		target = variablesBuffer[expressionToIterate.name]
		if target.type == "source":
			print("FOUND ERROR: variableAssigned:'{}' and source:'{}' sanitizers:'{}'".format(variableName, target.name, sanitizerFunctionsPassed))
			if pattern["vulnerability"] not in variablesBuffer[variableName].errors.keys():
				variablesBuffer[variableName].errors[pattern["vulnerability"]] = []
			variablesBuffer[variableName].errors[pattern["vulnerability"]].append(createVariableErrorObject(target.name, sanitizerFunctionsPassed))
		
		if target.tainted == True and target.name != variableName:
			print("Copying errors from {} to variableAssigned: {}".format(target.name,variableName))
			vulnerabilityName = pattern["vulnerability"]
			if vulnerabilityName not in target.errors.keys():
				return
			if vulnerabilityName not in variablesBuffer[variableName].errors.keys():
				variablesBuffer[variableName].errors[vulnerabilityName] = []
			for error in target.errors[vulnerabilityName]:
				if len(sanitizerFunctionsPassed) != 0:
					errorCopy = copy.deepcopy(error)
					for sanitizer in errorCopy["sanitized flows"]:
						sanitizer += sanitizerFunctionsPassed
					if len(errorCopy["sanitized flows"]) == 0:
						errorCopy["sanitized flows"] += sanitizerFunctionsPassed
						print(sanitizerFunctionsPassed)
					variablesBuffer[variableName].errors[vulnerabilityName].append(errorCopy)
					print("Updated Sanitizers: ",variablesBuffer[variableName].errors[vulnerabilityName])
				else:
					variablesBuffer[variableName].errors[vulnerabilityName].append(error)
		
		if target.tainted == True and target.name == variableName:
			print("Updating sanitized paths from {} to variableAssigned: {}".format(target.name,variableName))
			print("Previous errors on {} -> {}".format(target.name, target.errors))
			vulnerabilityName = pattern["vulnerability"]
			#print(target.errors)
			#variable = target (in this case)
			if vulnerabilityName not in target.errors.keys():
				target.errors[vulnerabilityName] = []
			for error in target.errors[vulnerabilityName]:
				if len(sanitizerFunctionsPassed) != 0:
					for sanitizer in error["sanitized flows"]:
						if sanitizerFunctionsPassed != sanitizer:
							sanitizer += sanitizerFunctionsPassed
					if len(error["sanitized flows"]) == 0:
						error["sanitized flows"] += sanitizerFunctionsPassed
						print(sanitizerFunctionsPassed)
			print("New error on {} -> {}".format(target.name, variablesBuffer[variableName].errors))

	elif isinstance(expressionToIterate, Function):
		#print("Entrei")
		if expressionToIterate.name in pattern["sanitizers"]:
			print("FOUND SANITIZED FUNCTION", expressionToIterate.name)
			#print("passed:" , sanitizerFunctionsPassed)
			if len(sanitizerFunctionsPassed) != 0:
				sanitizerFunctionsUpdate = copy.deepcopy(sanitizerFunctionsPassed)
				sanitizerFunctionsUpdate.append(expressionToIterate.name)
			else:
				sanitizerFunctionsUpdate = [expressionToIterate.name]
			#print("update:" , sanitizerFunctionsUpdate)
			for argument in expressionToIterate.argsList:
				checkErrors(pattern, variablesBuffer, variableName, argument, sanitizerFunctionsUpdate)
			return

		if expressionToIterate.name in pattern["sources"]:
			print("FOUND ERROR: variableName:'{}' and source:'{}' sanitizers:'{}'".format(variableName, expressionToIterate.name, sanitizerFunctionsPassed))
			if pattern["vulnerability"] not in variablesBuffer[variableName].errors.keys():
				variablesBuffer[variableName].errors[pattern["vulnerability"]] = []
			variablesBuffer[variableName].errors[pattern["vulnerability"]].append(createVariableErrorObject(expressionToIterate.name, sanitizerFunctionsPassed))	
			#VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(sinkName, expressionToIterate.name, sanitizerFunctionsPassed))

		for argument in expressionToIterate.argsList:
			checkErrors(pattern, variablesBuffer, variableName, argument, sanitizerFunctionsPassed)
			#iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, argument, sanitizerFunctionsPassed)
	
	elif isinstance(expressionToIterate, Expression):
		checkErrors(pattern, variablesBuffer, variableName, expressionToIterate.leftSide, sanitizerFunctionsPassed)
		checkErrors(pattern, variablesBuffer, variableName, expressionToIterate.rightSide, sanitizerFunctionsPassed)
		#iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate.leftSide, sanitizerFunctionsPassed)
		#iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate.rightSide, sanitizerFunctionsPassed)
	
	#else:
		#print("target was '{}'".format(expressionToIterate))


def iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate, sanitizerFunctionsPassed):
	print("expression on iterate: ", expressionToIterate)
	if isinstance(expressionToIterate, Variable):
		#print("Entrei")
		target = variablesBuffer[expressionToIterate.name]
		if target.type == "source":
			print("ADDING ERROR: sink:'{}' and source:'{}' sanitizers:'{}'".format(sinkName, target.name, sanitizerFunctionsPassed))
			VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(sinkName, target.name, sanitizerFunctionsPassed))

		for vulnerabilityName in target.errors.keys():
			for error in target.errors[vulnerabilityName]:
				print("ADDING COPIED ERROR: sink:'{}' and source:'{}' sanitizers:'{}'".format(sinkName, error["source"], error["sanitized flows"]))
				if len(sanitizerFunctionsPassed) != 0:
					errorCopy = copy.deepcopy(error)
					for sanitizer in errorCopy["sanitized flows"]:
						sanitizer += sanitizerFunctionsPassed
					if len(errorCopy["sanitized flows"]) == 0:
						errorCopy["sanitized flows"] += sanitizerFunctionsPassed
					VulnerabilitiesReport.addError(vulnerabilityName,createErrorObjectFromVariableError(sinkName, errorCopy))
				else:
					VulnerabilitiesReport.addError(vulnerabilityName,createErrorObjectFromVariableError(sinkName, error))

	elif isinstance(expressionToIterate, Function):
		#print("Entrei")
		if expressionToIterate.name in pattern["sanitizers"]:
			#print("passed:" , sanitizerFunctionsPassed)
			if len(sanitizerFunctionsPassed) != 0:
				sanitizerFunctionsUpdate = copy.deepcopy(sanitizerFunctionsPassed)
				sanitizerFunctionsUpdate.append(expressionToIterate.name)
			else:
				sanitizerFunctionsUpdate = [expressionToIterate.name]
			#print("update:" , sanitizerFunctionsUpdate)
			for argument in expressionToIterate.argsList:
				iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, argument, sanitizerFunctionsUpdate)
			return

		if expressionToIterate.name in pattern["sources"]:
			print("ADDED ERROR: sink:'{}' and source:'{}' sanitizers:'{}'".format(sinkName, expressionToIterate.name, sanitizerFunctionsPassed))
			VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(sinkName, expressionToIterate.name, sanitizerFunctionsPassed))

		for argument in expressionToIterate.argsList:
			iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, argument, sanitizerFunctionsPassed)
	
	elif isinstance(expressionToIterate, Expression):
		iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate.leftSide, sanitizerFunctionsPassed)
		iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate.rightSide, sanitizerFunctionsPassed)
	
	#else:
		#print("target was '{}'".format(expressionToIterate))


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

def updateErrorsOnRelatedVariables(pattern, variablesBuffer, variableNameWithNewErrors):
	#print(variablesBuffer)
	for variableName in variablesBuffer.keys():
		if variableNameWithNewErrors in variablesBuffer[variableName].variablesThatNotTaint:
			if pattern["vulnerability"] not in variablesBuffer[variableName].errors.keys():
				variablesBuffer[variableName].errors[pattern["vulnerability"]] = []
			copiedErrors = copy.deepcopy(variablesBuffer[variableNameWithNewErrors].errors[pattern["vulnerability"]])
			print("copied Errors from {} to {}: {} ".format(variableNameWithNewErrors, variableName, copiedErrors))
			variablesBuffer[variableName].errors[pattern["vulnerability"]] += copiedErrors 
			if variablesBuffer[variableName].type == "sink" and len(copiedErrors) != 0:
				for error in copiedErrors:
					VulnerabilitiesReport.addError(pattern["vulnerability"],
													createErrorObjectFromVariableError(variableName, error))
			print("new Errors in {} -> {}".format(variableName,variablesBuffer[variableName].errors[pattern["vulnerability"]] ))

		#else:
			#return
			#Update with new sanitizers -> How to know which error need to update
			#for error in variablesBuffer[variableName].errors[pattern["vulnerability"]]:
				#if error["source"] == variableNameWithNewErrors: WRONG variableNameWithNewErrors == VariableThatMadeThatError
				#	error["sanitized flows"] = variablesBuffer[variableNameWithNewErrors].errors




def populateVariablesThatNotTaint(pattern, variablesBuffer, targetVariableName, expressionToIterate, bodyListStatements):
	if isinstance(expressionToIterate, Variable):
		if not variablesBuffer[expressionToIterate.name].isTainted(pattern, variablesBuffer, bodyListStatements):
			variablesBuffer[targetVariableName].variablesThatNotTaint.append(expressionToIterate.name)
	
	if isinstance(expressionToIterate, Function):
		for argument in expressionToIterate.argsList:
			populateVariablesThatNotTaint(pattern, variablesBuffer, targetVariableName, argument, [])

	if isinstance(expressionToIterate, Expression):
		populateVariablesThatNotTaint(pattern, variablesBuffer, targetVariableName, expressionToIterate.leftSide, [])
		populateVariablesThatNotTaint(pattern, variablesBuffer, targetVariableName, expressionToIterate.rightSide, [])