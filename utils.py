class Constant:
	def __init__(self, value):
		self.level = "none"
		self.value = value
	
	def __repr__(self) -> str:
		return 'Constant(%s)' % (self.value)
	
	def isTainted(self, parameters, variablesBuffer):
		return False

class Variable:
	def __init__(self, name):
		self.name = name 
		self.tainted = False
		self.type = "none"

	def __repr__(self) -> str:
		return 'Variable(%s)' % (self.name)

	def isTainted(self, pattern, variablesBuffer):
		return variablesBuffer[self.name].tainted

class Break:
	def __init__(self): 
		return
	def __repr__(self) -> str:
		return 'Break()'
	
	def isTainted():
		return False


class Function:
	def __init__(self, name, argsList):
		self.name = name
		self.argsList = argsList 
	
	def __repr__(self) -> str:
		return 'Function(%s, %s)' % (self.name, self.argsList)

	def isTainted(self, pattern, variablesBuffer):
		#source(?) -> taint
		if self.name in pattern["sources"]:
			print("Che pintei logo FUNCTION '{}'".format(self.name))
			return True

		argumentsTainted = []
		for argument in self.argsList:
			if isinstance(argument, Variable):
				object = variablesBuffer[argument.name]
			else:
				object = argument

			isTaint = object.isTainted(pattern, variablesBuffer)
			if isTaint:
				argumentsTainted.append(object)
		
		#sink(taint) -> taint !!!ERROR -> ITERATE on path of expressionTainted AND FIND THE SOURCES
							#ASSOCIATED and save in a global variable !!! TODO

		if self.name in pattern["sinks"] and len(argumentsTainted) != 0:
			#ERROR !!!ITERATE on path of expressionTainted AND FIND THE SOURCES
							#ASSOCIATED and save in a global variable !!! TODO
			print("CHE PINTOU na FUNCTION '{}'".format(self.name))
			return True
			
class Expression:
	def __init__(self, left, right):
		self.left = left
		self.right = right
	
	def __repr__(self) -> str:
		return 'Expression(%s, %s)' % (self.left, self.right)

	def isTainted(self):
		self.left.isTainted()
		self.right.isTainted()

class Body:
	#Statements is a list of objects of the class Statement
	def __init__(self, statementsList):
		self.statementsList = statementsList
	
	def __repr__(self) -> str:
		result = ""
		for statement in self.statementsList:
			result += '\n' + str(statement)
		return 'Body(%s)' % (result)

	def isTainted(self):
		for statement in self.statementsList:
			statement.isTainted()

# class CompoudStatements:
# 	def __init__(self, first, second):
# 		self.firstStattement = first
# 		self.secondStatement = second

# 	def isTainted(self):
# 		self.firstStattement.isTainted()
# 		self.secondStatement.isTainted()

class Statement:
	pass

class Assignment(Statement):
	def __init__(self, variable, expression):
		self.variable = variable
		self.expression = expression
	
	def __repr__(self) -> str:
		return 'Assignment(%s, %s)' % (self.variable, self.expression)

	def isTainted(self, pattern, variablesBuffer):
		isVariableTainted = variablesBuffer[self.variable.name].isTainted(pattern, variablesBuffer)
		isExpressionTainted = self.expression.isTainted(pattern, variablesBuffer)
		
		#sink = tainted -> !!!ITERATE on path of expressionTainted AND FIND THE SOURCES
							#ASSOCIATED and save in a global variable !!! TODO
		#source = ? -> tainted
		#tainted = untainted -> untainted ?????? -> CHECK with someone later
		#? = tainted -> tainted
		#? = untainted -> untainted

		if (self.variable.name in pattern["sinks"]) and isExpressionTainted:
			#ITERATE on path of expressionTainted AND FIND THE SOURCES
			#ASSOCIATED and save in a global variable #TODO
			print("CHE PINTOU no Assignment")
			return True
		elif self.variable.name in pattern["sources"]:
			return True
		elif isExpressionTainted:
			variablesBuffer[self.variable.name].tainted = True
			variablesBuffer[self.variable.name].path = self.expression
			print("Ché no Assignment pintei a variavel '{}'".format(self.variable.name))
			return True	
		else:
			return False
	

class If(Statement):
	def __init__(self, condition, thenBlock, elseBlock):
		self.condition = condition
		self.thenBlock = thenBlock
		self.elseBlock = elseBlock

	def __repr__(self) -> str:
		return 'If(Condition: %s, ThenBlock: %s, ElseBlock: %s)' % (self.condition, self.thenBlock, self.elseBlock)

	def isTainted(self):
		self.condition.isTainted()
		self.thenBlock.isTainted()
		self.elseBlock.isTainted()

class While(Statement):
	def __init__(self, condition, block):
		self.condition = condition
		self.block = block
	
	def __repr__(self) -> str:
		return 'While(Condition: %s, block: %s)' % (self.condition, self.block)

	def isTainted(self):
		self.condition.isTainted()
		self.block.isTainted()