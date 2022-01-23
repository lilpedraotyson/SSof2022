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
		self.path = None
		self.assigned = False

	def __repr__(self) -> str:
		return 'Variable(%s)' % (self.name)

	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		if variablesBuffer[self.name].assigned == False:
			variablesBuffer[self.name].tainted = True
			variablesBuffer[self.name].type = "source"

		return variablesBuffer[self.name].tainted

class Break:
	def __init__(self): 
		return
	def __repr__(self) -> str:
		return 'Break()'
	
	def isTainted(pattern, variablesBuffer, bodyListStatements):
		return False


class Function:
	def __init__(self, name, argsList):
		self.name = name
		self.argsList = argsList 
	
	def __repr__(self) -> str:
		return 'Function(%s, %s)' % (self.name, self.argsList)

	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		#source(?) -> taint
		if self.name in pattern["sources"]:
			return True

		argumentsTainted = []
		#print("Function Name: " , self.name)
		#print("Arguments: " , self.argsList)
		for argument in self.argsList:
			isTaint = argument.isTainted(pattern, variablesBuffer, bodyListStatements)
			if isTaint:
				argumentsTainted.append(argument)
		
		#print("arguments Tainted of function {} : {}".format(self.name, argumentsTainted))
		
		#sink(taint) -> taint !!!ERROR -> ITERATE on path of expressionTainted AND FIND THE SOURCES
							#ASSOCIATED and save in a global variable !!! TODO

		if self.name in pattern["sinks"] and len(argumentsTainted) != 0:
			#ERROR !!!ITERATE on path of expressionTainted AND FIND THE SOURCES
							#ASSOCIATED and save in a global variable !!! TODO
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
			count += 1
			if(count >= len(bodyStatementsList)):	
				statement.isTainted(pattern, variablesBuffer, [])
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
		#isVariableTainted = variablesBuffer[self.variable.name].isTainted(pattern, variablesBuffer)
		isExpressionTainted = self.expression.isTainted(pattern, variablesBuffer, bodyListStatements)
		
		#print(self.expression)
		#sink = tainted -> !!!ITERATE on path of expressionTainted AND FIND THE SOURCES
							#ASSOCIATED and save in a global variable !!! TODO
		#source = ? -> tainted
		#tainted = untainted -> untainted ?????? -> CHECK with someone later
		#? = tainted -> tainted
		#? = untainted -> untainted

		if variablesBuffer[self.variable.name].type == "sink" and isExpressionTainted:
			#ITERATE on path of expressionTainted AND FIND THE SOURCES
			#ASSOCIATED and save in a global variable #TODO
			variablesBuffer[self.variable.name].tainted = True
			variablesBuffer[self.variable.name].path = self.expression
			iterateAndFindSourceOfError(pattern,variablesBuffer, self.variable.name, self.expression, [])
			variablesBuffer[self.variable.name].assigned = True
			return True
		elif variablesBuffer[self.variable.name].type == "source":
			#Only saves path if right side is tainted
			if isExpressionTainted:
				variablesBuffer[self.variable.name].path = self.expression
			variablesBuffer[self.variable.name].assigned = True
			return True
		elif isExpressionTainted:
			variablesBuffer[self.variable.name].tainted = True
			variablesBuffer[self.variable.name].path = self.expression
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

		ifVariablesBuffer = copy.deepcopy(variablesBuffer)
		ifPattern = copy.deepcopy(pattern)
		if len(bodyStatementsList) != 0:
			bodyStatementsListIf = copy.deepcopy(bodyStatementsList)
		else:
			bodyStatementsListIf = []

		self.elseBlock.isTainted(elsePattern, elseVariablesBuffer, bodyStatementsListElse)
		# count = 0
		# for statement in bodyStatementsList:
		# 	count += 1
		# 	if(count >= len(bodyStatementsList)):	
		# 		statement.isTainted(elsePattern, elseVariablesBuffer, [])
		# 	statement.isTainted(elsePattern, elseVariablesBuffer, bodyStatementsList[count:])
		
		self.thenBlock.isTainted(ifPattern, ifVariablesBuffer, bodyStatementsListIf)
		# count = 0
		# for statement in bodyStatementsList:
		# 	count += 1
		# 	if(count >= len(bodyStatementsList)):	
		# 		statement.isTainted(ifPattern, ifVariablesBuffer, [])
		# 	else:
		# 		statement.isTainted(ifPattern, ifVariablesBuffer, bodyStatementsList[count:])



class While(Statement):
	def __init__(self, condition, block):
		self.condition = condition
		self.block = block
	
	def __repr__(self) -> str:
		return 'While(Condition: %s, block: %s)' % (self.condition, self.block)

	def isTainted(self, pattern, variablesBuffer, bodyListStatements):
		self.condition.isTainted(pattern, variablesBuffer, bodyListStatements)
		self.block.isTainted(pattern, variablesBuffer, bodyListStatements)

def createErrorObject(sinkName, sourceName, sanitizerFunctionsPassed):
	return {"source": sourceName, "sink": sinkName, "sanitized flows": sanitizerFunctionsPassed}

def iterateAndFindSourceOfError(pattern, variablesBuffer, sinkName, expressionToIterate, sanitizerFunctionsPassed):
	print(expressionToIterate)
	if isinstance(expressionToIterate, Variable):
		target = variablesBuffer[expressionToIterate.name]
		if target.type == "source":
			VulnerabilitiesReport.addError(pattern["vulnerability"], createErrorObject(sinkName, target.name, sanitizerFunctionsPassed))
		
		iterateAndFindSourceOfError(pattern,variablesBuffer, sinkName, target.path, sanitizerFunctionsPassed)

	elif isinstance(expressionToIterate, Function):
		if expressionToIterate.name in pattern["sanitizers"]:
			print("passed:" , sanitizerFunctionsPassed)
			if len(sanitizerFunctionsPassed) != 0:
				sanitizerFunctionsUpdate = copy.deepcopy(sanitizerFunctionsPassed)
				sanitizerFunctionsUpdate.append(expressionToIterate.name)
			else:
				sanitizerFunctionsUpdate = [expressionToIterate.name]
			print("update:" , sanitizerFunctionsUpdate)
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
	
	else:
		print("target was '{}'".format(expressionToIterate))