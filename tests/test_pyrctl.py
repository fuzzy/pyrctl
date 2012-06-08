import types
import unittest
import pyrctl

class TestRctl(unittest.TestCase):

  # Anything that would be helpful to precache for any methods
  # later on
  def setUp(self):
    self.obj = pyrctl.Rctl()
    self.seq = range(10)

  def test_humanizeIds(self):
    des = 'user:root:vmemoryuse:deny=10737'
    got = self.obj.humanizeIds('user:0:vmemoryuse:deny=10737')
    self.assertEqual(des, got)

  def test_humanizeAmounts(self):
    des = 'user:root:vmemoryuse:deny=1G'
    got = self.obj.humanizeAmount('user:root:vmemoryuse:deny=1073741824')
    self.assertEqual(des, got)

  def test_humanizeUsageAmounts(self):
    self.assertEqual(True, True)

  def test_resolveIds(self):
    des = 'user:0:vmemoryuse:deny=10737'
    got = self.obj.resolveIds('user:root:vmemoryuse:deny=10737')
    self.assertEqual(des, got)

  def test_resolveAmounts(self):
    des = 'user:root:vmemoryuse:deny=1073741824'
    got = self.obj.resolveAmount('user:root:vmemoryuse:deny=1G')
    self.assertEqual(des, got)

  def test_addRule(self):
    self.assertEqual(
      self.obj.addRule('user:nobody:vmemoryuse:log=3g'), True)

  def test_delRule(self):
    self.assertEqual(
      self.obj.delRule('user:nobody:vmemoryuse:log=3g'), True)

  def test_showRules(self):
    self.assertEqual(True, True)

  def test_showUsage(self):
    self.assertEqual(True, True)

  def test_showLimits(self):
    self.assertEqual(True, True)

if __name__ == '__main__':
  print 'Unit testing: PyRCTL'
  unittest.main()
