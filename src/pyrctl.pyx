###
### Python Imports
###
import re

###
### Exceptions
###

class InvalidUserName(Exception):
  pass

class InvalidUserId(Exception):
  pass

class InvalidLoginClass(Exception):
  pass

class InvalidJailName(Exception):
  pass

class InvalidJailId(Exception):
  pass

###
### Cython Imports
###

cdef extern from "jail.h":
  int   jail_getid(char *name)
  char *jail_getname(int jid)

cdef extern from "sys/rctl.h":
  # These are syscalls, and will fail if you are not root.
  int	rctl_get_racct(char *ib, size_t ibl, char *ob, size_t obl)
  int	rctl_get_limits(char *ib, size_t ibl, char *ob, size_t obl)
  int	rctl_get_rules(char *ib, size_t ibl, char *ob, size_t obl)
  int rctl_add_rule(char *ib, size_t ibl, char *ob, size_t obl)
  int rctl_remove_rule(char *ib, size_t ibl, char *ob, size_t obl)

###
### Classes
###

class RctlBackend:
  def __init__(self):
    self.__UserMap  = self.__getUserMap()

  def _join(self, sep=':', seq=None):
    if seq:
      retv = ''
      for itm in range(0,len(seq)):
        if itm < (len(seq)-1):
          retv += seq[itm]+sep
        else:
          retv += seq[itm]
      return retv
    else:
      return None

  def __getUserMap(self):
    retv = {
      'users':  [], # This will reference only uname, uid, gname and gid
      'groups': [], # This will have all the groups, with gname, gid,
                    # and a list of tuples, one for each user, with uid
                    # and uname
      'logins': [], # Login class list, for simple verification.
      'jails':  []  # TODO: Jail list of tuples.
    }
    
    # First let's get our /etc/{passwd,group} files read in, so we can
    # build our map, which will be so neat and shiny.
    # Read in /etc/passwd
    fp = open('/etc/passwd', 'r')
    passwd = []
    while 1:
      buf = fp.readline()
      if not buf: break
      if buf[0] != '#':
        passwd.append(buf.strip().split('#')[0].split(':'))
    fp.close()
    
    # Read in /etc/group
    fp = open('/etc/group', 'r')
    group = []
    while 1:
      buf = fp.readline()
      if not buf: break
      if buf[0] != '#':
        group.append(buf.strip().split('#')[0].split(':'))
    fp.close()
    
    # Read in /etc/login.conf
    fp = open('/etc/login.conf', 'r')
    login = []
    while 1:
      buf = fp.readline()
      if not buf: break
      if re.match('^[a-zA-Z0-9]*:.*$', buf):
        retv['logins'].append(buf.strip().split(':')[0])
        
    # And now lets build our map
    # First lets parse up our users
    for user in passwd:
      tmp = {
        'uname': user[0],
        'uid':   user[2],
        'gid':   user[3]
      }
      for grp in group:
        if tmp['gid'] == grp[2]:
          tmp['gname'] = grp[0]
      retv['users'].append(tmp)
    
    # Then lets parse up our groups
    for grp in group:
      tmp = {
        'gname':   grp[0],
        'gid':     grp[2],
        'members': grp[3].split(',')
      }
      if len(tmp['members']) > 0:
        for un in range(0,len(tmp['members'])):
          for usr in retv['users']:
            if usr['uname'] == tmp['members'][un]:
              tmp['members'][un] = usr
      retv['groups'].append(tmp)

    return retv

  def __refreshUserMap(self):
    self.__UserMap  = self.__getUserMap()

  def resolveIds(self, rule=None):
    self.__refreshUserMap()
    if rule:
      rule_s = rule.split(':')
      if rule_s[0] == 'user':
        for usr in self.__UserMap['users']:
          if rule_s[1] == usr['uname']:
            rule_s[1] = usr['uid']
            break
        if not str(rule_s[1]).isdigit():
          raise InvalidUserName
      elif rule_s[0] == 'jail':
        r = jail_getid(rule_s[1])
        if r != -1:
          rule_s[1] = str(r)
        else:
          raise InvalidJailId
      elif rule_s[0] == 'loginclass':
        if not self.__UserMap['logins'].__contains__(rule_s[1]):
          raise InvalidLoginClass
        
      return self._join(':', rule_s)
  
  def humanizeIds(self, rule=None):
    self.__refreshUserMap()
    if rule:
      rule_s = rule.split(':')
      if rule_s[0] == 'user' and rule_s[1].isdigit():
        for usr in self.__UserMap['users']:
          if rule_s[1] == usr['uid']:
            rule_s[1] = usr['uname']
            break
        if not rule_s[1].isalnum():
          raise InvalidUserName
      elif rule_s[0] == 'jail' and rule_s[1].isdigit():
        s = jail_getname(int(rule_s[1]))
        if s:
          rule_s[1] = s
        else: raise InvalidJailName
      elif rule_s[0] == 'loginclass':
        if not self.__UserMap['logins'].__contains__(rule_s[1]):
          raise InvalidLoginClass
      
      return self._join(':', rule_s)
  
  def resolveAmount(self, amount=None):
    ''' user:username:vmemoryuse:deny=1g '''
    self.__refreshUserMap()
    if amount:
      retv_s = amount.split(':')
      if retv_s[-1:][0].find('=') != -1 and len(retv_s) == 4:
        (action, amount) = retv_s[-1:][0].split('=')
        if amount.isalnum():
          flag = amount[-1:]
          if flag.lower() == 'k':
            amount_r = str(int(amount[:-1])*1024)
          elif flag.lower() == 'm':
            amount_r = str(int(amount[:-1])*(1024**2))
          elif flag.lower() == 'g':
            amount_r = str(int(amount[:-1])*(1024**3))
          elif flag.lower() == 't':
            amount_r = str(int(amount[:-1])*(1024**4))
          elif flag.lower() == 'p':
            amount_r = str(int(amount[:-1])*(1024**5))
          else:
            amount_r = amount[:-1]
          retv_s[len(retv_s)-1] = action+'='+amount_r
      
      return self._join(':', retv_s)

  def humanizeAmount(self, rule=None):
    self.__refreshUserMap()
    if rule:
      rule_s = rule.split(':')
      if rule_s[-1:][0].find('=') != -1 and len(rule_s) == 4:
        (actn, amnt) = rule_s[-1:][0].split('=')
        if amnt.isdigit():
          if int(amnt) >= 1024 and int(amnt) < (1024**2):
            amnt_r = str(int(amnt) / 1024)+'K'
          elif int(amnt) >= (1024**2) and int(amnt) < (1024**3):
            amnt_r = str(int(amnt) / (1024**2))+'M'
          elif int(amnt) >= (1024**3) and int(amnt) < (1024**4):
            amnt_r = str(int(amnt) / (1024**3))+'G'
          elif int(amnt) >= (1024**4) and int(amnt) < (1024**5):
            amnt_r = str(int(amnt) / (1024**4))+'T'
          elif int(amnt) >= (1024**5):
            amnt_r = str(int(amnt) / (1024**5))+'P'
          else:
            amnt_r = str(amnt+'b')
          rule_s[len(rule_s)-1] = actn+'='+amnt_r
        
      return self._join(':', rule_s)

  def humanizeUsageAmount(self, usage=None):
    if usage:
      for key in usage.keys():
        if str(usage[key]).isdigit():
          amnt = int(usage[key])
          if amnt >= 1024 and amnt < (1024**2):
            amnt_r = str(float(amnt) / 1024.0)+'K'
          elif amnt >= (1024**2) and amnt < (1024**3):
            amnt_r = '%.02fM' % (float(amnt) / (1024.0**2.0))
          elif amnt >= (1024**3) and amnt < (1024**4):
            amnt_r = '%.02fG' % (float(amnt) / (1024.0**3.0))
          elif amnt >= (1024**4) and amnt < (1024**5):
            amnt_r = '%.02fT' % (float(amnt) / (1024.0**4.0))
          elif amnt >= (1024**5):
            amnt_r = '%.02fP' % (float(amnt) / (1024.0**5.0))
          else:
            amnt_r = str(amnt)+'b'
          usage[key] = amnt_r
      return usage

  def resolve(self, rule=None):
    if rule:
      return self.resolveIds(self.resolveAmount(rule))

  def humanize(self, rule=None):
    if rule:
      return self.humanizeIds(self.humanizeAmount(rule))


class Rctl(RctlBackend):
  def __init__(self):
    RctlBackend.__init__(self)
    pass

  def showLimits(self, pid=None):
    cdef char  *obuff = ''
    cdef size_t oblen = 4096*4
    cdef char  *ibuff = ''
    cdef size_t iblen = len(ibuff)+1
    retv              = []
    tmp               = 'process:'+str(pid)
    ibuff             = tmp
    
    retc = rctl_get_limits(ibuff, iblen, obuff, oblen)
    for rle in obuff.strip().split(','):
      retv.append(self.humanize(rle))
      
    return retv

  def showRules(self, rule='::'):
    cdef char  *obuff = ''
    cdef size_t oblen = 4096*4
    cdef char  *ibuff = rule
    cdef size_t iblen = len(ibuff)+1
    retv              = []
    
    retc  = rctl_get_rules(ibuff, iblen, obuff, oblen)
    for rle in obuff.strip().split(','):
      if rule == '::':
        retv.append(self.humanize(rle))
      elif self.humanize(rle).find(self.humanize(rule)) != -1:
        retv.append(self.humanize(rle))
    
    return retv

  def showUsage(self, rule=None):
    rule = self.resolve(rule)
    cdef char  *obuff = ''
    cdef size_t oblen = 4096*4
    cdef char  *ibuff = ''
    cdef size_t iblen = 0
    if rule:
      retv            = {}
      ibuff           = rule
      iblen           = len(rule)+1

      error = rctl_get_racct(ibuff, iblen, obuff, oblen)
      for rle in obuff.strip().split(','):
        (key, val) = rle.split('=')
        retv[key] = val
      
      return self.humanizeUsageAmount(retv)
    else: return False

  def addRule(self, rule=None):
    if rule:
      rule = self.resolve(rule)
      if rctl_add_rule(rule, len(rule)+1, "", 0) == 0:
        return True
      else: return False

  def delRule(self, rule=None):
    if rule:
      rule = self.resolve(rule)
      if rctl_remove_rule(rule, len(rule)+1, "", 0) == 0:
        return True
      else: return False

