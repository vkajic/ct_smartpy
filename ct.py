import smartpy as sp

profile = sp.TRecord(
  pubkey = sp.TKey,  #public key of the profile owner, can be derived from a pwd based seed (key stretching)
  pubkey_old = sp.TKey,  #in case of unauthorized pwd change (centralized backend abuse), old public key (old pwd) still valid for a certain time period. during the same period withdrawals not possible
  pwdChangedAtBlock = sp.TNat,
  pwdChangedBy = sp.TNat,  #0 - default, 1 - pwd was changed by changePwd, 2 - pwd was changed by changePwdManaged, 3 - pwd was changed by resetPwd
  clientInfoHash = sp.TString,
  clientScore = sp.TNat,
  clientNumJobs = sp.TNat,
  clientTasks = sp.TList(sp.TNat),
  flancerInfoHash = sp.TString,
  flancerScore = sp.TNat,
  flancerNumJobs = sp.TNat,
  flancerTasks = sp.TList(sp.TNat),
  active = sp.TBool,
  managed = sp.TNat,
  version = sp.TNat,
  local = sp.TNat,
  )

task = sp.TRecord(
  client = sp.TNat,
  infoHash = sp.TString,
  status = sp.TNat,
  published = sp.TBool,
  #application section START
  #application can be in ACCEPTED while an individual milestone can be FINISHED.
  #If a milestone is CANCELED or REJECTED then so is the whole application
  applicationStage = sp.TMap(sp.TNat, sp.TNat),
  appliedList = sp.TMap(sp.TNat, sp.TNat),
  lastAppliedIndex = sp.TNat,
  acceptedList = sp.TMap(sp.TNat, sp.TNat),
  lastAcceptedIndex = sp.TNat,
  #milestone mappings START here
  #profile_index*10 + milestone_index
  #each application can have max 10 milestones, ie flancer1 would have milestones
  #as indices 10 to 19, flancer2 20-29 etc
  mstoneWorkplan = sp.TMap(sp.TNat, sp.TString),
  mstoneValue = sp.TMap(sp.TNat, sp.TNat),
  mstoneWorkTime = sp.TMap(sp.TNat, sp.TNat),
  mstoneEscrow = sp.TMap(sp.TNat, sp.TNat),
  mstoneStage = sp.TMap(sp.TNat, sp.TNat),
  mstoneSolution = sp.TMap(sp.TNat, sp.TString),
  #milestone mappings END here
  feedbacks = sp.TMap(sp.TNat, sp.TNat),
  #application section END
  version = sp.TNat,
  local = sp.TNat,
)

feedback = sp.TRecord(
  taskID = sp.TNat,
  flancer = sp.TNat,
  clientsScore = sp.TNat,
  clientsText = sp.TString,
  flancersScore = sp.TNat,
  flancersText = sp.TString,
  version = sp.TNat,
)

class CT(sp.Contract):
  def __init__(self, owner):
    self.init(
      owner = owner,
      locked = False,
      profiles = sp.big_map({}, tkey = sp.TNat, tvalue = profile),
      tasks = sp.big_map({}, tkey = sp.TNat, tvalue = task),
      feedbacks = sp.big_map({}, tkey = sp.TNat, tvalue = feedback),
      lastTaskIndex = 0,
      lastProfileIndex = 0,
      lastFeedbackIndex = 0,
      keyToProfile = sp.big_map({}, tkey = sp.TKey, tvalue = sp.TNat),
      logicVersion = 1,
      timePeriod = 8640,      #3 days assuming 30 second block time
      nonces = sp.big_map({}, tkey = sp.TKey, tvalue = sp.TNat),
      results = sp.big_map({}, tkey = sp.TKey, tvalue = sp.TNat)
    )

  def getMyProfile(self, pubkey):
    sp.verify(self.data.keyToProfile.contains(pubkey))
    pi = self.data.keyToProfile[pubkey]
    sp.verify(pi > 0)
    profile = self.data.profiles[pi]
    sp.verify(profile.pubkey == pubkey)
    return (profile, pi)

  @sp.entry_point
  def signUp(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, clientInfoHash = sp.TString,
      flancerInfoHash = sp.TString, managed = sp.TNat, local = sp.TNat
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      ("clientInfoHash", ("flancerInfoHash", ("managed", "local")))))))) ) )
    sp.verify(params.functionName == "signUp")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.clientInfoHash,
      params.flancerInfoHash, params.managed, params.local) )))
    #check if pubkey is already in use
    sp.verify(~self.data.keyToProfile.contains(params.pubkey))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    pi = sp.compute(self.data.lastProfileIndex + 1)
    self.data.keyToProfile[params.pubkey] = pi
    self.data.profiles[pi] = sp.record(pubkey = params.pubkey, pubkey_old = params.pubkey,
      pwdChangedAtBlock = 0, pwdChangedBy = 0, clientInfoHash = params.clientInfoHash,
      clientScore = 0, clientNumJobs = 0, clientTasks = [], flancerInfoHash = params.flancerInfoHash,
      flancerScore = 0, flancerNumJobs = 0, flancerTasks = [], active = True,
      managed = params.managed, version = 1, local = params.local)
    self.data.lastProfileIndex = pi
    self.data.results[params.pubkey] = pi

  @sp.entry_point
  def editProfile(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, clientInfoHash = sp.TString,
      flancerInfoHash = sp.TString, managed = sp.TNat
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      ("clientInfoHash", ("flancerInfoHash", "managed"))))))) ) )
    sp.verify(params.functionName == "editProfile")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.clientInfoHash,
      params.flancerInfoHash, params.managed) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    self.data.profiles[pi].clientInfoHash = params.clientInfoHash
    self.data.profiles[pi].flancerInfoHash = params.flancerInfoHash
    self.data.profiles[pi].managed = params.managed

  @sp.entry_point
  def changePwd(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, pubkey_new = sp.TKey
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      "pubkey_new"))))) ) )
    sp.verify(params.functionName == "changePwd")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.pubkey_new) )))
    #check if new pubkey is already in use
    sp.verify(~self.data.keyToProfile.contains(params.pubkey_new))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    #check if the time period has passed
    sp.verify(sp.level - profile.pwdChangedAtBlock > self.data.timePeriod)
    self.data.keyToProfile[params.pubkey_new] = pi
    self.data.profiles[pi].pubkey_old = params.pubkey
    self.data.profiles[pi].pubkey = params.pubkey_new
    self.data.profiles[pi].pwdChangedAtBlock = sp.level
    self.data.profiles[pi].pwdChangedBy = 1

  #centralized backend can change pwd for a managed account
  @sp.entry_point
  def changePwdManaged(self, params):
    sp.set_type(params, sp.TRecord(pi = sp.TNat, pubkey_new = sp.TKey
      ).layout( ("pi", "pubkey_new") ) )
    #only contract owner can call this function
    sp.verify(sp.sender == self.data.owner)
    profile = self.data.profiles[params.pi]
    #profile needs to be in managed state
    sp.verify(profile.managed > 0)
    #check that the new pubkey is not already in use
    sp.verify(~self.data.keyToProfile.contains(params.pubkey_new))
    #check if the time period has passed
    sp.verify(sp.level - profile.pwdChangedAtBlock > self.data.timePeriod)
    self.data.keyToProfile[params.pubkey_new] = params.pi
    self.data.profiles[params.pi].pubkey_old = profile.pubkey
    self.data.profiles[params.pi].pubkey = params.pubkey_new
    self.data.profiles[params.pi].pwdChangedAtBlock = sp.level
    self.data.profiles[params.pi].pwdChangedBy = 2

  #reset to the old pwd if within the time period, used if user thinks that
  #centralized backend abused changePwdManaged
  @sp.entry_point
  def resetPwd(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", "functionName")))) ) )
    sp.verify(params.functionName == "resetPwd")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    sp.verify(self.data.keyToProfile.contains(params.pubkey))
    pi = self.data.keyToProfile[params.pubkey]
    profile = self.data.profiles[pi]
    #check that profile was owned by the transaction signer
    sp.verify(profile.pubkey_old == params.pubkey)
    #check that the time period has not yet passed
    sp.verify(sp.level - profile.pwdChangedAtBlock < self.data.timePeriod)
    #pwd reset possible only after changePwdManaged
    sp.verify(profile.pwdChangedBy == 2)
    #self.data.keyToProfile[params.pubkey] = pi
    self.data.profiles[pi].pubkey = params.pubkey
    self.data.profiles[pi].pwdChangedAtBlock = sp.level
    self.data.profiles[pi].pwdChangedBy = 3

  @sp.entry_point
  def postTask(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, infoHash = sp.TString, local = sp.TNat
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      ("infoHash", "local")))))) ) )
    sp.verify(params.functionName == "postTask")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.infoHash,
      params.local) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    ti = sp.compute(self.data.lastTaskIndex + 1)
    self.data.tasks[ti] = sp.record(client = pi, infoHash = params.infoHash,
      status = 0, published = True, applicationStage = {}, appliedList = {},
      lastAppliedIndex = 0, acceptedList = {}, lastAcceptedIndex = 0,
      mstoneWorkplan = {}, mstoneValue = {}, mstoneWorkTime = {}, mstoneEscrow = {},
      mstoneStage = {}, mstoneSolution = {}, feedbacks = {}, version = 1, local = params.local)
    self.data.lastTaskIndex = ti
    self.data.profiles[pi].clientTasks.push(ti)
    self.data.results[params.pubkey] = ti

  @sp.entry_point
  def editTask(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, ti = sp.TNat, infoHash = sp.TString
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      ("ti", "infoHash")))))) ) )
    sp.verify(params.functionName == "editTask")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.ti,
      params.infoHash) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    task = self.data.tasks[params.ti]
    #you can only edit your own task
    sp.verify(task.client == pi)
    self.data.tasks[params.ti].infoHash = params.infoHash

  @sp.entry_point
  def closeApplications(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, ti = sp.TNat
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName", "ti"))))) ) )
    sp.verify(params.functionName == "closeApplications")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.ti) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    task = self.data.tasks[params.ti]
    #you can only close your own task
    sp.verify(task.client == pi)
    self.data.tasks[params.ti].status = 1

  @sp.entry_point
  def reopenApplications(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, ti = sp.TNat
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName", "ti"))))) ) )
    sp.verify(params.functionName == "reopenApplications")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.ti) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    task = self.data.tasks[params.ti]
    #you can only reopen your own task
    sp.verify(task.client == pi)
    #task needs to be in filled status
    sp.verify(task.status == 1)
    self.data.tasks[params.ti].status = 2

  @sp.entry_point
  def applyForTask(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, ti = sp.TNat
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName", "ti"))))) ) )
    sp.verify(params.functionName == "applyForTask")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.ti) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    #freelancer profile not set
    sp.verify(profile.flancerInfoHash != "")
    task = self.data.tasks[params.ti]
    #you cannot apply on your own tasks
    sp.verify(task.client != pi)
    #check if user already applied
    sp.verify(~task.applicationStage.contains(pi))
    #check that task is opened to applications
    sp.verify((task.status == 0) | (task.status == 2))
    li = sp.compute(task.lastAppliedIndex + 1)
    self.data.tasks[params.ti].appliedList[li] = pi
    self.data.tasks[params.ti].lastAppliedIndex = li
    self.data.tasks[params.ti].applicationStage[pi] = 0
    self.data.tasks[params.ti].mstoneStage[pi*10] = 0
    #save current task infoHash as mstoneWorkplan
    #(in case the client edits the task description later), as milestone0
    self.data.tasks[params.ti].mstoneWorkplan[pi*10] = task.infoHash
    self.data.profiles[pi].flancerTasks.push(params.ti)

  #limitted number of accepted flancers
  #after accepting a flancer, task status set to 1 (filled) - indicates the task
  #is not open to new freelancer applications, can be reopened later
  @sp.entry_point
  def acceptForTask(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, ti = sp.TNat, flancer = sp.TNat
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      ("ti", "flancer")))))) ) )
    sp.verify(params.functionName == "acceptForTask")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.ti, params.flancer) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    task = self.data.tasks[params.ti]
    #you can only accept freelancers for your own tasks
    sp.verify(task.client == pi)
    #this freelancer has not applied
    sp.verify(task.applicationStage.contains(params.flancer))
    #application must be in status 0 (just opened, not in progress)
    sp.verify(task.applicationStage[params.flancer] == 0)
    li = sp.compute(task.lastAcceptedIndex + 1)
    self.data.tasks[params.ti].acceptedList[li] = params.flancer
    self.data.tasks[params.ti].lastAcceptedIndex = li
    self.data.tasks[params.ti].applicationStage[params.flancer] = 1
    self.data.tasks[params.ti].mstoneStage[params.flancer*10] = 1
    self.data.tasks[params.ti].status = 1

  #client accepts flancer's work
  @sp.entry_point
  def finalize(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, ti = sp.TNat, flancer = sp.TNat,
      flancersScore = sp.TNat, flancersText = sp.TString
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      ("ti", ("flancer", ("flancersScore", "flancersText")))))))) ) )
    sp.verify(params.functionName == "finalize")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.ti, params.flancer,
      params.flancersScore, params.flancersText) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    task = self.data.tasks[params.ti]
    #you can only finalize applications on your own tasks
    sp.verify(task.client == pi)
    #this freelancer is not working on this task
    sp.verify(task.applicationStage.contains(params.flancer))
    #application must be in status 1 (in progress)
    sp.verify(task.applicationStage[params.flancer] == 1)
    self.data.tasks[params.ti].applicationStage[params.flancer] = 2
    self.data.tasks[params.ti].mstoneStage[params.flancer*10] = 2
    fi = sp.compute(self.data.lastFeedbackIndex + 1)
    sp.verify((params.flancersScore >= 1) & (params.flancersScore <= 5) &
      (params.flancersText != ""))
    self.data.feedbacks[fi] = sp.record(taskID = params.ti, flancer = params.flancer,
      clientsScore = 0, clientsText = "", flancersScore = params.flancersScore,
      flancersText = params.flancersText, version = 1)
    self.data.lastFeedbackIndex = fi
    self.data.tasks[params.ti].feedbacks[params.flancer] = fi
    profileFlancer = self.data.profiles[params.flancer]
    self.data.profiles[params.flancer].flancerScore = sp.compute(profileFlancer.flancerScore
      + params.flancersScore)
    self.data.profiles[params.flancer].flancerNumJobs = sp.compute(profileFlancer.flancerNumJobs
      + 1)
    self.data.results[params.pubkey] = fi

  #flancer can leave feedback after client cancelled an active work contract (application)
  #or after client accepted flancer's solution
  @sp.entry_point
  def leaveFeedbackFlancer(self, params):
    sp.set_type(params, sp.TRecord(pubkey = sp.TKey, sig = sp.TSignature, logicVersion = sp.TNat,
      nonce = sp.TNat, functionName = sp.TString, ti = sp.TNat,
      clientsScore = sp.TNat, clientsText = sp.TString
      ).layout( ("pubkey", ("sig", ("logicVersion", ("nonce", ("functionName",
      ("ti", ("clientsScore", "clientsText"))))))) ) )
    sp.verify(params.functionName == "leaveFeedbackFlancer")
    sp.verify(params.logicVersion == self.data.logicVersion)
    sp.verify(sp.check_signature(params.pubkey, params.sig, sp.pack(
      (params.logicVersion, params.nonce, params.functionName, params.ti,
      params.clientsScore, params.clientsText) )))
    sp.if self.data.nonces.contains(params.pubkey):
     sp.verify(params.nonce == self.data.nonces[params.pubkey])
     self.data.nonces[params.pubkey] += 1
    sp.else:
      sp.verify(params.nonce == 0)
      self.data.nonces[params.pubkey] = 1
    getMyProfileResult = self.getMyProfile(params.pubkey)
    profile = getMyProfileResult[0]
    pi = getMyProfileResult[1]
    task = self.data.tasks[params.ti]
    #you are not working on this task
    sp.verify(task.applicationStage.contains(pi))
    sp.verify((task.applicationStage[pi] == 2) | (task.applicationStage[pi] == 4))
    fi = task.feedbacks[pi]
    feedback = self.data.feedbacks[fi]
    sp.verify((params.clientsScore >= 1) & (params.clientsScore <= 5) &
      (params.clientsText != ""))
    #check that feedback was not already set
    sp.verify(feedback.clientsScore == 0)
    self.data.feedbacks[fi].clientsScore = params.clientsScore
    self.data.feedbacks[fi].clientsText = params.clientsText
    profileClient = self.data.profiles[task.client]
    self.data.profiles[task.client].clientScore = sp.compute(profileClient.clientScore +
      params.clientsScore)
    self.data.profiles[task.client].clientNumJobs = sp.compute(profileClient.clientNumJobs
      + 1)
    self.data.results[params.pubkey] = fi



@sp.add_test(name = "CT test")
def test():
    creator = sp.test_account("Creator")
    alice = sp.test_account("Alice")
    bob = sp.test_account("Bob")

    c1 = CT(creator.address)
    scenario  = sp.test_scenario()
    scenario.h1("CT test")
    scenario += c1

    pubkey = alice.public_key
    logicVersion = c1.data.logicVersion

    nonce = sp.nat(0)
    functionName = "signUp"
    clientInfoHash = "hihi"
    flancerInfoHash = "hayhay"
    managed = sp.nat(1)
    local = sp.nat(1)
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, clientInfoHash, flancerInfoHash, managed, local) ),
      message_format = "Raw")
    c1.signUp(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, clientInfoHash = clientInfoHash,
      flancerInfoHash = flancerInfoHash, managed = managed, local = local
      ).run(sender = creator)

    nonce = sp.nat(1)
    functionName = "editProfile"
    clientInfoHash = "hoho"
    flancerInfoHash = "huhu"
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, clientInfoHash, flancerInfoHash, managed) ),
      message_format = "Raw")
    c1.editProfile(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, clientInfoHash = clientInfoHash,
      flancerInfoHash = flancerInfoHash, managed = managed
      ).run(sender = creator)

    nonce = sp.nat(2)
    functionName = "changePwd"
    pubkeyNew = sp.key("edpkvQP4ZMJHVBwNCpxtcvVoX6N9joZ2gM6UNin8B8q5bMAMPckdv1")
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, pubkeyNew) ),
      message_format = "Raw")
    scenario.h2("sp.level is 0 in test env, that is why timeperiod cond fails")
    c1.changePwd(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, pubkey_new = pubkeyNew
      ).run(valid = False, sender = creator)

    nonce = sp.nat(2)
    functionName = "postTask"
    infoHash = "brm brm"
    local = sp.nat(1)
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, infoHash, local) ),
      message_format = "Raw")
    c1.postTask(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, infoHash = infoHash,
      local = local
      ).run(sender = creator)

    nonce = sp.nat(3)
    functionName = "editTask"
    ti = 1
    infoHash = "piki piki"
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti, infoHash) ),
      message_format = "Raw")
    c1.editTask(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti, infoHash = infoHash
      ).run(sender = creator)

    nonce = sp.nat(4)
    functionName = "closeApplications"
    ti = 1
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti) ),
      message_format = "Raw")
    c1.closeApplications(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti
      ).run(sender = creator)

    nonce = sp.nat(5)
    functionName = "reopenApplications"
    ti = 1
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti) ),
      message_format = "Raw")
    c1.reopenApplications(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti
      ).run(sender = creator)


    bobpubkey = bob.public_key
    nonce = sp.nat(0)
    functionName = "signUp"
    clientInfoHash = ""
    flancerInfoHash = "tomtom"
    managed = sp.nat(1)
    local = sp.nat(1)
    sig = sp.make_signature(bob.secret_key, sp.pack( (logicVersion,
      nonce, functionName, clientInfoHash, flancerInfoHash, managed, local) ),
      message_format = "Raw")
    c1.signUp(pubkey = bobpubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, clientInfoHash = clientInfoHash,
      flancerInfoHash = flancerInfoHash, managed = managed, local = local
      ).run(sender = creator)

    nonce = sp.nat(1)
    functionName = "applyForTask"
    ti = 1
    sig = sp.make_signature(bob.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti) ),
      message_format = "Raw")
    c1.applyForTask(pubkey = bobpubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti
      ).run(sender = creator)


    nonce = sp.nat(6)
    functionName = "acceptForTask"
    ti = 1
    flancer = 2
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti, flancer) ),
      message_format = "Raw")
    c1.acceptForTask(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti, flancer = flancer
      ).run(sender = creator)

    nonce = sp.nat(7)
    functionName = "finalize"
    ti = 1
    flancer = 2
    flancersScore = 6
    flancersText = "odlicno"
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti, flancer, flancersScore, flancersText) ),
      message_format = "Raw")
    scenario.h2("fail on score equal or less than 5 condition")
    c1.finalize(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti, flancer = flancer,
      flancersScore = flancersScore, flancersText = flancersText).run(
      valid = False, sender = creator)

    nonce = sp.nat(7)
    functionName = "finalize"
    ti = 1
    flancer = 2
    flancersScore = 5
    flancersText = "odlicno"
    sig = sp.make_signature(alice.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti, flancer, flancersScore, flancersText) ),
      message_format = "Raw")
    c1.finalize(pubkey = pubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti, flancer = flancer,
      flancersScore = flancersScore, flancersText = flancersText).run(sender = creator)


    nonce = sp.nat(2)
    functionName = "leaveFeedbackFlancer"
    ti = 1
    clientsScore = 4
    clientsText = "vrlo dobro"
    sig = sp.make_signature(bob.secret_key, sp.pack( (logicVersion,
      nonce, functionName, ti, clientsScore, clientsText) ),
      message_format = "Raw")
    c1.leaveFeedbackFlancer(pubkey = bobpubkey, sig = sig, logicVersion = logicVersion,
      nonce = nonce, functionName = functionName, ti = ti,
      clientsScore = clientsScore, clientsText = clientsText).run(sender = creator)



sp.add_compilation_target("ct",
  CT(owner = sp.address("tz1bLisMsWWBUtLYir5nFmH6xHasshTe67DG")))
    