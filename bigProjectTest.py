import unittest


#TEST SUITE PRESENT
#COVERAGE ≈ 0%
class TestStringMethods(unittest.TestCase):

    def test_upper(self):
        self.assertEqual('lowercase'.upper(), 'LOWERCASE')



if __name__ == '__main__':
    unittest.main()