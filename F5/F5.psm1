#######################################################################################################################
# File:             F5.psm1                                                                                           #
# Author:           Bryan Johnson                                                                                     #
# Publisher:        The Active Network, Inc.                                                                          #
# Copyright:        Â© 2013 The Active Network, Inc. All rights reserved.                                             #
#######################################################################################################################

function Import-PSCredential {
	param ( $Path = "credentials.enc.xml" )

	# Import credential file
	Write-Host "Importing credentials from $Path"
	$import = Import-Clixml $Path 
	
	# Test for valid import
	if ( !$import.UserName -or !$import.EncryptedPassword ) {
		Throw "Input is not a valid ExportedPSCredential object, exiting."
	}
	$Username = $import.Username
	if ($Username.StartsWith('\')) {
		$Username = $Username.SubString(1,$Username.length - 1)
	}
	# Decrypt the password and store as a SecureString object for safekeeping
	$SecurePass = $import.EncryptedPassword | ConvertTo-SecureString
	
	# Build the new credential object
	$Credential = New-Object System.Management.Automation.PSCredential $Username, $SecurePass

	Write-Output $Credential
}

function F5Initialize {
	param ($BigIP, $Credential) 
	if ( (Get-PSSnapin | Where-Object { $_.Name -eq "iControlSnapIn"}) -eq $null )  {
		Add-PSSnapIn iControlSnapIn
  	}
	try {
  		$result = Initialize-F5.iControl -HostName $Bigip -Credentials $Credential
	}
	catch [Exception] {
		$result = $false
	}
	return $result
}

function Test-F5HttpProfile {
	param ($HttpProfile)
	
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()

	$ProfileName = $HttpProfile.name
	$f5HttpProfile = "/$Partition/$ProfileName"
	$HttpProfiles = (Get-F5.iControl).LocalLBProfileHttp.get_list()

	$ProfileExists = $false
	foreach ($hprofile in $HttpProfiles) {
		if ($hprofile -eq $f5HttpProfile) {
			$ProfileExists = $true
			break
		}
	}
	return $ProfileExists
}


function New-F5HttpProfile {
	param($HttpProfile)

	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
	$ProfileName = $HttpProfile.name
	$f5profile = "/$Partition/$ProfileName"
	
	$ProfileExists = Test-F5HttpProfile -HttpProfile $HttpProfile
	if ($ProfileExists) {
		Write-Host "   HttpProfile $ProfileName already exists."
	}
	
	else {
		Write-Host "Creating HttpProfile: $ProfileName"
		(Get-F5.iControl).LocalLBProfileHttp.create($ProfileName)
	
		if ($HttpProfile.fallback_host) {
			$ProfileString = New-Object -TypeName iControl.LocalLBProfileString
			$ProfileString.default_flag = $false
			$ProfileString.value = $HttpProfile.fallback_host
	
			(Get-F5.iControl).LocalLBProfileHttp.set_fallback_host_name($ProfileName, $ProfileString)
		}
		
		if ($HttpProfile.header_insert) {
			$ProfileString = New-Object -TypeName iControl.LocalLBProfileString
			$ProfileString.default_flag = $false
			$ProfileString.value = $HttpProfile.header_insert

			(Get-F5.iControl).LocalLBProfileHttp.set_header_insert($ProfileName, $ProfileString)
		}
		
		if ($HttpProfile.insert_xforwarded_for_header_mode -eq "enabled") {
			$ProfileMode = New-Object -TypeName iControl.LocalLBProfileProfileMode
			$ProfileMode.default_flag = $false
			$ProfileMode.value = "PROFILE_MODE_ENABLED"
			
			(Get-F5.iControl).LocalLBProfileHttp.set_insert_xforwarded_for_header_mode($ProfileName, $ProfileMode)
		}
		Write-Host "SUCCESS: $ProfileName created"
	}
}

function Remove-F5HttpProfile {
	param($HttpProfile)
	
	$ProfileName = $HttpProfile.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()

	$ProfileExists = Test-F5HttpProfile -HttpProfile $HttpProfile
	if ($ProfileExists) {
		Write-Host "Removing http profile $ProfileName"
		try {
			(Get-F5.iControl).LocalLBProfileHttp.delete_profile($ProfileName)
			Write-Host "SUCCESS: Removal complete"
		}
		catch [System.Management.Automation.MethodInvocationException] {

			Write-Host "NOTICE: Removal of http profile failed."
			$error = $_.Exception.Message -match 'error_string.*:(.+)$'
			Write-Host $matches[1]
			Write-Host Continuing...
		}
	}
	else {
			Write-Host "$ProfileName does not exist."
	}
}

function Set-F5Context {
	param ($Partition)
	
	(Get-F5.iControl).ManagementPartition.set_active_partition( (,$Partition) )
	(Get-F5.iControl).ManagementPartition.get_active_Partition()
}

#
# Monitor Template Functions
#

function Test-F5MonitorTemplate {
  param($MonitorTemplate)
  
  	$TemplateName = $MonitorTemplate.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
	$f5TemplateName = "/$Partition/$TemplateName"

	$TemplateExists = $false
	$TemplateList = $(Get-F5.iControl).LocalLBMonitor.get_template_list()
	foreach($Template in $TemplateList) {
		if ( $Template.template_name.Equals($F5TemplateName) ) {
			$TemplateExists = $true
			break
		}
	}
	$TemplateExists
}

function New-F5MonitorTemplate {
  param($MonitorTemplate)
 	
	$TemplateName = $MonitorTemplate.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
  	$f5Monitor = "/$Partition/$TemplateName"

	if (Test-F5MonitorTemplate -MonitorTemplate $MonitorTemplate) 		{
		Write-Host "   Monitor Template $TemplateName already exists"
	}
	else {
		$ConfigAttributes = $MonitorTemplate.attributes
		
		$Template = New-Object -TypeName iControl.LocalLBMonitorMonitorTemplate
		$Template.template_name = $MonitorTemplate.name
		$Template.template_type = $MonitorTemplate.type

		$TemplateAttribute = New-Object -TypeName iControl.LocalLBMonitorCommonAttributes
		$TemplateAttribute.parent_template = $ConfigAttributes.parent_template
		$TemplateAttribute.interval = $ConfigAttributes.interval
		$TemplateAttribute.timeout = $ConfigAttributes.timeout

		$TemplateAttribute.dest_ipport = New-Object -TypeName iControl.LocalLBMonitorIPPort
		$TemplateAttribute.dest_ipport.ipport = New-Object -TypeName iControl.CommonIPPortDefinition
			
		if ($ConfigAttributes.alias_service_port -eq '*') {
			$TemplateAttribute.dest_ipport.address_type = "ATYPE_STAR_ADDRESS_STAR_PORT"
			$TemplateAttribute.dest_ipport.ipport.address = "0.0.0.0"
			$TemplateAttribute.dest_ipport.ipport.port = 0
		} else {
			$TemplateAttribute.dest_ipport.address_type = "ATYPE_STAR_ADDRESS_EXPLICIT_PORT"
			$TemplateAttribute.dest_ipport.ipport.address = "0.0.0.0"
			$TemplateAttribute.dest_ipport.ipport.port = [string]$ConfigAttributes.alias_service_port	
		}

		if ($ConfigAttributes.is_read_only -eq "true") {
			$TemplateAttribute.is_read_only = $true
		}
		else {
			$TemplateAttribute.is_read_only = $false
		}
		
		if ($ConfigAttributes.is_directly_usable -eq "true") {
			$TemplateAttribute.is_directly_usable = $true
		}
		else {
			$TemplateAttribute.is_directly_usable = $false
		}

		$(Get-F5.iControl).LocalLBMonitor.create_template(
			(, $Template),
			(, $TemplateAttribute)
		)

		$StringValues = @()
		
		$StringValues += New-Object -TypeName iControl.LocalLBMonitorStringValue
		$StringValues[0].type = "STYPE_SEND"
		$StringValues[0].value = $MonitorTemplate.send

		$StringValues += New-Object -TypeName iControl.LocalLBMonitorStringValue
		$StringValues[1].type = "STYPE_RECEIVE"
		$StringValues[1].value = $MonitorTemplate.receive

		# Set HTTP Specific attributes
		$(Get-F5.iControl).LocalLBMonitor.set_template_string_property(
			($TemplateName,$TemplateName),
			$StringValues
		)

		Write-Host "Monitor $TemplateName succesfully created"
	}
}

function Remove-F5MonitorTemplate {
	param($MonitorTemplate)
	
	$TemplateName = $MonitorTemplate.name
	
	Write-Host "Removing monitor template:" $TemplateName
	$MonitorTemplateExists = Test-F5MonitorTemplate -MonitorTemplate $MonitorTemplate
	if ($MonitorTemplateExists) {
		try {
			$(Get-F5.iControl).LocalLBMonitor.delete_template( (,$TemplateName) )
			Write-Host "SUCCESS: Removal complete"
		}
		catch [System.Management.Automation.MethodInvocationException] {

			Write-Host "NOTICE: Removal of monitor template failed."
			$error = $_.Exception.Message -match 'error_string.*:(.+)$'
			Write-Host $matches[1]
			Write-Host Continuing...
		}
	}
	else {
		Write-Host "Monitor template does not exist"
	}
}

function Test-F5Node {
	param($Node)

	$NodeName = $Node.keys
	$IP = $Node.$($NodeName)
	
	$NodeExists = $false
	$NodeList = (Get-F5.iControl).LocalLBNodeAddress.get_list()
	foreach ($N in $NodeList) {
		if ($N -eq $IP) {
			$NodeExists = $true
			break
		}
	}
	return $NodeExists
}

function New-F5Node {
	param($Node)
	
	$NodeName = $Node.keys
	$IP = $Node.$($NodeName)
	
	if (Test-F5Node -Node $Node) {
		Write-Host "   Node $NodeName already exists"
	}
	else {
		(Get-F5.iControl).LocalLBNodeAddressV2.create($NodeName, $IP, 0)
	}
}

function Remove-F5Node {
	param($Node)
	
	$NodeName = $Node.Keys
	
	$f5nodes = (Get-F5.iControl).LocalLBNodeAddress.get_list()
	foreach ($f5node in $f5nodes) {
		if ($f5node -eq $Node[$NodeName]) {
			(Get-F5.iControl).LocalLBNodeAddress.delete_node_address($Node[$NodeName])
			Write-Host "Node '$NodeName' deleted"
		}
	}	
}


#
# Pool Functions
#
function Test-F5Pool {
	param($Pool)

	$PoolName = $Pool.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
  	$f5Pool = "/$Partition/$PoolName"

	$PoolExists = $false
	$PoolList = $(Get-F5.iControl).LocalLBPool.get_list()
	foreach($P in $PoolList) {
		if ( $P.Equals($f5Pool) ) {
			$PoolExists = $true;
			break
		}
	}
	return $PoolExists
}

function Remove-F5Pool {
	param($Pool)
	
	$PoolName = $Pool.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()

	if ( Test-F5Pool -Pool $Pool) {
		$(Get-F5.iControl).LocalLBPool.delete_pool( (,$PoolName) )
		Write-Host "Deleted Pool $NameName"
	}
}


function New-F5Pool{
	param($Pool)

	$PoolName = $Pool.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
		
	if ( Test-F5Pool -Pool $Pool) {
		Write-Host "   Pool $PoolName already exists"
	}
	else {
		$PoolMembers = $Pool.members
		
		#Create Nodes
		foreach ($N in $PoolMembers.Keys) {
			$Nodeinfo = @{$N = $PoolMembers.$N}
			New-F5Node -Node $Nodeinfo
		}
			
		#Create member array
		$Node_A = @()
		foreach ($PoolMember in $PoolMembers.Keys) {
			$Node = New-Object -TypeName iControl.CommonIPPortDefinition;
			$Node.address = $PoolMembers.$PoolMember
			$Node.port = $Pool.http_port
			$Node_A += $Node
			$Node = $null
		}

		#CreatePool
		(Get-F5.iControl).LocalLBPool.create(
	    	(,$PoolName),
	    	(,$Pool.lb_method),
	    	(,$Node_A)
	    )
		
		(Get-F5.iControl).LocalLBPool.set_allow_nat_state(
			(,$PoolName),
			(,$Pool.allow_nat)
		)
		
		(Get-F5.iControl).LocalLBPool.set_allow_snat_state(
			(,$PoolName),
			(,$Pool.allow_snat)
		)

		(Get-F5.iControl).LocalLBPool.set_action_on_service_down(
			(,$PoolName),
			(,$Pool.action_on_service_down)
		)

		(Get-F5.iControl).LocalLBPool.set_slow_ramp_time(
			(,$PoolName),
			(,[long]$Pool.slow_ramp_time)
		)
		Write-Host "Created Pool $PoolName" 	
	}
}

function Add-F5HealthMonitors {
	param(
		$Pool
	)
  
	$monitor_association = New-Object -TypeName iControl.LocalLBPoolMonitorAssociation
	$monitor_association.pool_name = $Pool.name
	$monitor_association.monitor_rule = New-Object -TypeName iControl.LocalLBMonitorRule

	$monitor_association.monitor_rule.quorum = 0
	$monitor_association.monitor_rule.monitor_templates = $Pool.health_monitors
	if ($Pool.health_monitors.count -gt 1) {
		$monitor_association.monitor_rule.type = "MONITOR_RULE_TYPE_AND_LIST"
	}
	else {
		$monitor_association.monitor_rule.type = "MONITOR_RULE_TYPE_SINGLE"
	}


	$(Get-F5.iControl).LocalLBPool.set_monitor_association(
		( , $monitor_association)
	)

	
  	foreach ($Monitor in $Pool.health_monitors) {
		Write-Host "Monitor $Monitor associated with pool $PoolName"
	}
}


function Test-F5HttpClassProfile {
	param ($HttpClassProfile)
	
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
	$HttpClassProfileName = $HttpClassProfile.name
	$f5HttpClassProfile = "/$Partition/$HttpClassProfileName"

	$HttpClassProfiles = (Get-F5.iControl).LocalLBProfileHttpClass.get_list()

	$profile_exists = $false
	foreach ($HCP in $HttpClassProfiles) {
		if ($HCP -eq $f5HttpClassProfile) {
			$profile_exists = $true
			break
		}
	}
	return $profile_exists
}


function New-F5HttpClassProfile {
	param($HttpClassProfile)

	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()	
	$HttpClassProfileName = $HttpClassProfile.name
	$f5profile = "/$Partition/$HttpClassProfileName"

	if (Test-F5HttpClassProfile -HttpClassProfile $HttpClassProfile) {
		Write-Host "   HttpClassProfile $HttpClassProfileName already exists"
	}
	else {
		Write-Host "Creating HttpClassProfile: $HttpClassProfileName"
		(Get-F5.iControl).LocalLBProfileHttpClass.create($HttpClassProfileName)
	
		$ProfileString = New-Object -TypeName iControl.LocalLBProfileString
		$ProfileString.default_flag = $false
		$ProfileString.value = $HttpClassProfile.redirect_location
	
		(Get-F5.iControl).LocalLBProfileHttpClass.set_redirect_location("$HttpClassProfileName", $ProfileString)
		Write-Host "SUCCESS: $HttpClassProfileName created"
	}
}

function Add-F5HttpClassProfiles {
	param ($Vip)
	
	$VipName = $Vip.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()

	foreach ($HCP in $Vip.http_class_profiles) {

		$f5HttpClassProfile = "/$Partition/$HCP"
		$profiles = (Get-F5.iControl).LocalLBVirtualServer.get_httpclass_profile($Vip.name)
		$associated = $profiles.profile_name -contains $f5HttpClassProfile
	
		if ($associated) {
			Write-Host "Http class profile '$HCP' is already assocaited with VIP '$VipNAME'"
		}
		else {
			$HttpClassProfile = New-Object -TypeName icontrol.LocalLBVirtualServerVirtualServerHttpClass
			$HttpClassProfile.profile_name = $HCP
			$HttpClassProfile.priority = 1
			
			(Get-F5.iControl).LocalLBVirtualServer.add_httpclass_profile($Vip.name, $HttpClassProfile)
			Write-Host "Added http class profile '$HCP' to VIP '$VipName'"
		}			
	}
}

function Remove-F5HttpClassProfile {
	param($HttpClassProfile)
	
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()	
	$HttpClassProfileName = $HttpClassProfile.name
	$f5profile = "/$Partition/$HttpClassProfileName"

	if (Test-F5HttpClassProfile -HttpClassProfile $HttpClassProfile) {
		Write-Host "Removing http class profile $HttpClassProfileName"
		try {
			(Get-F5.iControl).LocalLBProfileHttpClass.delete_profile($HttpClassProfileName)
			Write-Host "SUCCESS: Removal complete"
		}
		catch [System.Management.Automation.MethodInvocationException] {

			Write-Host "NOTICE: Removal of http class profile $HttpClassProfileName failed"
			$error = $_.Exception.Message -match 'error_string.*:(.+)$'
			Write-Host $matches[1]
			Write-Host Continuing...
		}
	}
	else {
		Write-Host "$HttpClassProfile does not exist"
	}
}

#
# iRule Functions
#
function Test-F5iRule {
	param([string]$Name)
	
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
   	$f5iRule = "/$Partition/$Name"

	try {
  		$iRule = (Get-F5.iControl).LocalLBRule.query_rule((,"$Name"))
		if ($iRule) {
			$iRuleExists = $true
		}
		else {
			$iRuleExists = $false
		}
	}
	catch [Exception] {
		$iRuleExists = $false
	}
	return $iRuleExists
}


function New-F5iRule {
	param([string]$Name,
		  [string]$Content
	)

	$Rules = @()

	if (Test-F5iRule -Name $Name) {
		Write-Host "   iRule `"$Name`" already exists"
	}
	else {
		$iRule = New-Object -TypeName icontrol.LocalLBRuleRuleDefinition
		$iRule.rule_name = $Name
		$iRule.rule_definition = $Content
		$Rules += $iRule
		(Get-F5.iControl).LocalLBRule.create($Rules)
	}
}

function Remove-F5iRule {
	param([string]$Name)

	write-host "Deleting iRule `"$Name`""
	if (Test-F5iRule -Name $Name) {
		try {				
			(Get-F5.iControl).LocalLBRule.delete_rule((,$Name))
		}
		catch [System.Management.Automation.MethodInvocationException] {

			Write-Host "NOTICE: Removal of iRule failed."
			$error = $_.Exception.Message -match 'error_string.*:(.+)$'
			Write-Host $matches[1]
			Write-Host Continuing...
		}
	}
	else {
		Write-Host "iRule `"$Name`" does not exist"
	}
}

function Add-F5iRule {
	param($Vip,
		  [string]$iRule,
		  [int]$Priority)
		  
	$VirtualServerRule = New-Object -TypeName iControl.LocalLBVirtualServerVirtualServerRule
	$VirtualServerRule.rule_name = $iRule
	$VirtualServerRule.priority = $Priority
	
	$VirtualServerRules = @()
	$VirtualServerRules += $VirtualServerRule
	
	$VipExists = (Test-F5Vip -Vip $Vip)
	$iRuleExists = (Test-F5iRule -Name $iRule)
	$iRuleAttached = $false
	
	$VipName = $Vip.name
	
	Write-Host "Adding iRule `"$iRule`" to $VipName"
	if ($VipExists) {
		if ($iRuleExists) {
			# See if it's already connected to the VIP
			$iRules = (Get-F5.iControl).LocalLBVirtualServer.get_rule((,"$VipName"))
			foreach ($Rule in $irules) {
				if ($Rule.rule_name -match $iRule) {
					$iRuleAttached = $true
				}
			}
			
			if ($iRuleAttached) {
				Write-Host "   $iRule already attached to $VipName"
			}
			else {
				(Get-F5.iControl).LocalLBVirtualServer.add_rule((,"$VipName"), ((,$VirtualServerRules)))
			}
		}
		else {
			Write-Host "FAILURE: iRule addition failed"
			Write-Host "    iRule `"$iRule`" does not exist"
		}
	}
	else {
		Write-Host "FAILURE: iRule addition failed"
		Write-Host "    $VipName does not exist"
	}
}


#
# VIP Functions
#

function Test-F5Vip {
	param($Vip)
  
  	$VipName = $Vip.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
   	$f5Vip = "/$Partition/$VipName"
	
	$VipExists = $false
	$Vips = (Get-F5.iControl).LocalLBVirtualServer.get_list()

	foreach($Vip in $Vips) {
		if ( $Vip -eq $f5Vip ) {
			$VipExists = $true
			break
		}
	}
	return $VipExists
}


function Remove-F5Vip {
	param($Vip)

	$VipName = $Vip.name
	$Partition = (Get-F5.iControl).ManagementPartition.get_active_Partition()
		
	if (Test-F5Vip -VIP $Vip) {
		$(Get-F5.iControl).LocalLBVirtualServer.delete_virtual_server( (,$VipName) )
		Write-Host "Deleted VIP '$VipName'"
	}
	else {
		Write-Host "VIP $VipName does not exist"
	}
}

function New-F5Vip {
  param($Vip)
	
	$VipName = $Vip.name
	
	if (Test-F5Vip -Vip $Vip) {
		Write-Host "   VIP '$VipName' already exists"
	}
	else {
		$definition = New-Object -TypeName iControl.CommonVirtualServerDefinition
	    $definition.name = $VipName
	    $definition.address = $Vip.address
	    $definition.port = $Vip.port
	    $definition.protocol = "PROTOCOL_TCP"
	    $definitions = (, $definition)
	    $wildmasks = (, "255.255.255.255")
	    $resource = New-Object -TypeName iControl.LocalLBVirtualServerVirtualServerResource
	    $resource.type = $Vip.type
	    $resource.default_pool_name = $Vip.default_pool
	    $resources = (, $resource)
		
		$ProfileA = @()
		$VipProfiles = $Vip.vip_profiles

		foreach ($VipProfile in ($VipProfiles.Keys)) {
			if ($VipProfiles.$VipProfile) {
				$ProfileInstance = New-Object -TypeName iControl.LocalLBVirtualServerVirtualServerProfile
				$ProfileInstance.profile_context = "PROFILE_CONTEXT_TYPE_ALL"
	    		$ProfileInstance.profile_name = $VipProfiles.$VipProfile
				$ProfileA += $ProfileInstance
				$ProfileInstance = $null
			}
		}
				
	    $ProfileAofA = (, $ProfileA)

	    Write-Host "Creating Virtual Server `"$VipName`"..."
	    
	    (Get-F5.iControl).LocalLBVirtualServer.create(
	      $definitions,
	      $wildmasks,
	      $resources,
	      $ProfileAofA
	    )
	    
		$ConnectionLimit = New-Object -TypeName iControl.CommonULong64
		$ConnectionLimit.high = $Vip.connection_limit
		$ConnectionLimit.low = $Vip.connection_limit
		(Get-F5.iControl).LocalLBVirtualServer.set_connection_limit(
			(,$VipName),
			(,$ConnectionLimit)
		)

		(Get-F5.iControl).LocalLBVirtualServer.set_enabled_state(
			(,$VipName),
			(,$Vip.enabled_state)
		)
		
		(Get-F5.iControl).LocalLBVirtualServer.set_translate_address_state(
			(,$VipName),
			(,$Vip.address_translation_state)
		)

		(Get-F5.iControl).LocalLBVirtualServer.set_translate_port_state(
			(,$VipName),
			(,$Vip.port_translation_state)
		)

		(Get-F5.iControl).LocalLBVirtualServer.set_source_port_behavior(
			(,$VipName),
			(,$Vip.source_port_behavior)
		)	
		
	    switch ($Vip.snat_pool) {
			automap {
				(Get-F5.iControl).LocalLBVirtualServer.set_snat_automap(
				(, $VipName)
				)
			}
			none {
				(Get-F5.iControl).LocalLBVirtualServer.set_snat_none(
				(, $VipName)
				)
			}
		}
		
		$ClonePoolAofA = @()
		if ($Vip.clone_pool_client -notmatch "none") {
			$ClonePoolClient = New-Object -TypeName iControl.LocalLBVirtualServerVirtualServerClonePool
			$ClonePoolClient.pool_name = $Vip.clone_pool_client
			$ClonePoolClient.type = "CLONE_POOL_TYPE_CLIENTSIDE"
			$ClonePoolAofA += $ClonePoolClient
		}
		
		if ($Vip.clone_pool_server -notmatch "none") {
			$ClonePoolServer = New-Object -TypeName iControl.LocalLBVirtualServerVirtualServerClonePool
			$ClonePoolServer.pool_name = $Vip.clone_pool_server
			$ClonePoolServer.type = "CLONE_POOL_TYPE_SERVERSIDE"
			$ClonePoolAofA += $ClonePoolServer
		}
		
		(Get-F5.iControl).LocalLBVirtualServer.add_clone_pool(
			(,$VipName),
			(,$ClonePoolAofA)
		)
				
		$default_persist = New-Object -TypeName iControl.LocalLBVirtualServerVirtualServerPersistence
		$default_persist.profile_name = $Vip.default_persistence_profile
		$default_persist.default_profile = $true
		
		$persistA = $default_persist
		$persistAofA = (,$persistA)
		$default_persist = $Vip.default_persistence_profile
		if ($default_persist) {
			(Get-F5.iControl).LocalLBVirtualServer.add_persistence_profile($VipName, $persistAofA)
		}
		
		$failback_persist = $Vip.failback_persistence_profile
		if ($failback_persist -and $default_persist) {
			(Get-F5.iControl).LocalLBVirtualServer.set_fallback_persistence_profile($VipName, $failback_persist)
		}
		
		if ($Vip.last_hop_pool -notmatch "none") {
			(Get-F5.iControl).LocalLBVirtualServer.set_last_hop_pool(
				(,$VipName),
				(,$Vip.last_hop_pool)
			)
		}
	}
}


Export-ModuleMember -Function *
