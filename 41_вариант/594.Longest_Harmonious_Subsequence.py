class Solution(object):
    def findLHS(self, nums):
        count = {}
        for i in nums:
            if i in count:
                count[i] += 1
            else:
                count[i] = 1
        res = 0
        for n in count:
            if n+1 in count:
                dl = count[n] + count[n+1]
                if dl > res:
                    res = dl
        return res
