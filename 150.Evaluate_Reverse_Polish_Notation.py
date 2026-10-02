class Solution(object):
    def evalRPN(self, tokens):
        stack = []
        operands = {"+", "-", "/", "*"}
        for token in tokens:
            if token in operands:
                b = stack.pop()
                a = stack.pop()
                if token == "+":
                    stack.append(a + b)
                elif token == "*":
                    stack.append(a * b)
                elif token == "-":
                    stack.append(a - b)
                elif token == "/":
                    stack.append(int(a / b))
            else:
                stack.append(int(token))
        return stack[0]
