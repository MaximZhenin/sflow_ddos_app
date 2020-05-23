include(scriptdir()+'/inc/trend.js');

var defaultGroups = {
    external:['0.0.0.0/0','::/0'],
    private:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','fc00::/7']
};

var defaultSettings = {
    ip_flood:{threshold:100, timeout:180, action:'ignore'},
    ip_fragmentation:{threshold:100, timeout:60, action:'ignore'},
    icmp_flood:{threshold:100, timeout:60, action:'ignore'},
    udp_amplification:{threshold:100, timeout:60, action:'ignore'},
    udp_flood:{threshold:100, timeout:60, action:'ignore'},
    tcp_flood:{threshold:100, timeout:60, action:'ignore'}
};
//Topology
var topology = storeGet('topology');
if(topology) setTopology(topology);
var members = storeGet('members') || {};

var macToMember = {};
var ipGroups = {};
var numMembers = 0;
var numMacs = 0;


var groups = storeGet('groups') || defaultGroups;
var externalGroup = getSystemProperty("ddos_protect.externalgroup") || 'external';
var excludedGroups = getSystemProperty("ddos_protect.excludedgroups") || 'external,private';

var flow_t = getSystemProperty("ddos_protect.flow_seconds") || '2';
var threshold_t = getSystemProperty("ddos_protect.threshold_seconds") || '2';
var effectiveSamplingRateThreshold = getSystemProperty("ddos_protect.esr_samples") || '10';

setGroups('ddos_protect', groups);
var settings = storeGet('settings') || defaultSettings;

// Counters
var controls = {};

var controlsUpdate = 0;
var counts = {};

var trend = new Trend(300,1); 
var points;



function updateControlCounts() {
  controlsUpdate++;
  counts = {n:0};
  for(var key in controls) {
    counts.n++;
  }
}

function applyControl(ctl) {
    ctl.action = settings[ctl.attack].action;
    logInfo("Action = " +  ctl.action);
    //if('ignore' === ctl.action) return;
  
    logInfo("DDoS "+ctl.action+" "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
    sendEvent(ctl.action,ctl.attack,ctl.target,ctl.group,ctl.protocol);
  
    controls[ctl.key] = ctl;

    updateControlCounts();
}


// find member macs
//setFlow('ix_ip4', {keys:'macsource,group:ipsource:ix_member',value:'bytes',log:true,flowStart:true, n:N, t:T, fs:SEP});
//setFlow('ix_ip6', {keys:'macsource,group:ip6source:ix_member',value:'bytes',log:true,flowStart:true, n:N, t:T, fs:SEP});

// IPv4 attacks
//предполагаю, что excludegruop может быть также подвержена ddos атакам
var keys = 'ipdestination,group:ipdestination:ddos_protect';
var filter = 'group:ipdestination:ddos_protect='+excludedGroups;
setFlow('ddos_protect_ip_flood', {
  keys: keys+',ipprotocol',
  value:'frames',
  filter:filter,
  t:flow_t
});
setFlow('ddos_protect_ip_fragmentation', {
  keys: keys+',ipprotocol',
  value:'frames',
  filter:'(ipflags=001|range:ipfragoffset:1=true)&'+filter,
  t:flow_t
});
setFlow('ddos_protect_udp_amplification', {
  keys:keys+',udpsourceport',
  value:'frames',
  filter:'ipprotocol=17&'+filter,
  t:flow_t
});
//


/*setFlow('udp_reflection',
 {keys:'ipdestination,udpsourceport',value:'frames'});*/

setFlow('ddos_protect_udp_flood', {
  keys:keys+',udpdestinationport',
  value:'frames',
  filter:'ipprotocol=17&'+filter,
  t:flow_t
});


//
setFlow('ddos_protect_icmp_flood', {
  keys:keys+',icmptype',
  value:'frames',
  filter:'ipprotocol=1&'+filter,
  t:flow_t
});
setFlow('ddos_protect_tcp_flood', {
  keys:keys+',tcpdestinationport',
  value:'frames',
  filter:'ipprotocol=6&'+filter,
  t:flow_t
});

// IPv6 attacks

/*setThreshold('ddos_protect_udp_flood',
 {metric:'udp_reflection',value:100,byFlow:true,timeout:2});*/
function setThresholds() {
  logInfo("SetThresholds");
    setThreshold('ddos_protect_ip_flood',
      {metric:'ddos_protect_ip_flood', value:settings.ip_flood.threshold, byFlow:true, timeout:threshold_t}
    );
    setThreshold('ddos_protect_icmp_flood',
      {metric:'ddos_protect_icmp_flood', value:settings.icmp_flood.threshold, byFlow:true, timeout:threshold_t}
    );
    setThreshold('ddos_protect_tcp_flood',
      {metric:'ddos_protect_tcp_flood', value:settings.tcp_flood.threshold, byFlow:true, timeout:threshold_t}
    );
    setThreshold('ddos_protect_udp_flood',
      {metric:'ddos_protect_udp_flood',value:settings.udp_flood.threshold,byFlow:true,timeout:threshold_t}
    );
    setThreshold('ddos_protect_udp_amplification',
      {metric:'ddos_protect_udp_amplification', value:settings.udp_amplification.threshold, byFlow:true, timeout:threshold_t}
    );
    setThreshold('ddos_protect_ip_fragmentation',
      {metric:'ddos_protect_ip_fragmentation', value:settings.ip_fragmentation.threshold, byFlow:true, timeout:threshold_t}
    );
    logInfo("endSetThresholds");
  }
  
  setThresholds();

var idx = 0;

setEventHandler(function(evt) {
  logInfo("SetEventHandler");
  var key = evt.thresholdID+'-'+evt.flowKey;
  if(controls[key]) return;

  // don't allow data from data sources with sampling rates close to threshold
  // avoids false positives due the insufficient samples
  if(false) {
    logInfo("dsInfo" + evt.agent + "     "+ evt.dataSource);
    let dsInfo = datasourceInfo(evt.agent,evt.dataSource);
    if(!dsInfo) return;
    let rate = dsInfo.effectiveSamplingRate;
    logInfo("rate = " + rate);
    logInfo("flow_t * evt.threshold / rate =  " + flow_t * evt.threshold / rate);
    if(!rate || flow_t * evt.threshold / rate < effectiveSamplingRateThreshold) {
      logWarning("DDoS effectiveSampling rate "+rate+" too high for "+evt.agent);
      return;
    }
  }
  logInfo("dsInfo Passed");
  var [target,group,protocol] = evt.flowKey.split(',');

  var ctl = {
    id:'c' + idx++,
    time:evt.timestamp,
    status:'pending',
    key:key,
    target:target,
    group:group,
    protocol:protocol,
    flowspec:{},
    event:evt,
    success:{}
  };
  logInfo("Choose");
  switch(evt.thresholdID) {   
    case 'ddos_protect_ip_flood':
      ctl.attack = 'ip_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'='+protocol
      };
      break;
    case 'ddos_protect_icmp_flood':
      logInfo("Icmp_flood Apear");
      ctl.attack = 'icmp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=1',
        'icmp-type':'='+protocol
      };
      break;
    case 'ddos_protect_tcp_flood':
      ctl.attack = 'tcp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=6',
        'destination-port':'='+protocol
      }; 
      break;
    case 'ddos_protect_udp_flood':
      logInfo("UDP_Apear");
      ctl.attack = 'udp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=17',
        'destination-port':'='+protocol
      };
      break;
    case 'ddos_protect_udp_amplification':
      ctl.attack = 'udp_amplification';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=17',
        'source-port':'='+protocol
      };
      break;
    case 'ddos_protect_ip_fragmentation':
      ctl.attack = 'ip_fragmentation';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'='+protocol,
        fragment:'=I'
      };
      break;
  }
  logInfo("ApplyControl");
  applyControl(ctl);
},[
 'ddos_protect_ip_flood',
 'ddos_protect_icmp_flood',
 'ddos_protect_tcp_flood',
 'ddos_protect_udp_flood',
 'ddos_protect_udp_amplification',
 'ddos_protect_ip_fragmentation'
]);

setIntervalHandler(function(now) {
  logInfo("SetInterval");
  points = {};
  points['controls'] = counts.n || 0;
  points['controls_pending'] = counts.pending || 0;
  points['controls_failed'] = counts.failed || 0;
  points['controls_blocked'] = counts.blocked || 0;
  //points['connections'] = routers.reduce((sum, router_ip) => sum + (bgpUp[router_ip] ? 1 : 0), 0);
 /* points['top-5-ip-flood'] = calculateTopN(['ddos_protect_ip_flood','ddos_protect_ip6_flood'],5,1);
  points['top-5-ip-fragmentation'] = calculateTopN(['ddos_protect_ip_fragmentation','ddos_protect_ip6_fragmentation'],5,1);
  points['top-5-udp-flood'] = calculateTopN(['ddos_protect_udp_flood','ddos_protect_udp6_flood'],5,1);
  points['top-5-udp-amplification'] = calculateTopN(['ddos_protect_udp_amplification','ddos_protect_udp6_amplification'],5,1);
  points['top-5-icmp-flood'] = calculateTopN(['ddos_protect_icmp_flood','ddos_protect_icmp6_flood'],5,1);
  points['top-5-tcp-flood'] = calculateTopN(['ddos_protect_tcp_flood','ddos_protect_tcp6_flood'],5,1);*/
  trend.addPoints(now,points);

  for(var key in controls) {
    var ctl = controls[key];
    if(now - ctl.time < settings[ctl.attack].timeout * 60000) continue;
    if(thresholdTriggered(ctl.threshold,ctl.agent,ctl.metric,key)) continue;

    delete controls[key];
  }
}, 5);

/*
var ryu = '127.0.0.1';
var controls = {};
var keys = 'ipdestination,group:ipdestination:ddos_protect';
setFlow('ddos_protect_udp_flood', {
  keys:keys+',udpdestinationport',
  value:'frames',
  filter:'ipprotocol=17&'+filter,
  t:flow_t
});

setFlow('udp_reflection',
 {keys:'ipdestination,udpsourceport',value:'frames'});
setThreshold('udp_reflection_attack',
 {metric:'udp_reflection',value:100,byFlow:true,timeout:2});

setEventHandler(function(evt) {
  logInfo("Hi");
 // don't consider inter-switch links
 var link = topologyInterfaceToLink(evt.agent,evt.dataSource);
 if(link) return;

 // get port information
 logInfo("Hi1");
 var port = topologyInterfaceToPort(evt.agent,evt.dataSource);
 if(!port) return;

 // need OpenFlow info to create Ryu filtering rule
 logInfo("Hi2");
 if(!port.dpid || !port.ofport) return;

 // we already have a control for this flow
 logInfo("Hi3");
 if(controls[evt.flowKey]) return;
 logInfo("Hi4");
 var [ipdestination,udpsourceport] = evt.flowKey.split(',');
 var msg = {
  priority:4000,
  dpid:port.dpid,
  match: {
   in_port:port.ofport,
   dl_type:0x800,
   nw_dst:ipdestination+'/32',
   nw_proto:17,
   tp_src:udpsourceport 
  }
 };
 logInfo("Hi5");

 logInfo("Hi6");
 controls[evt.flowKey] = {
  time:Date.now(),
  threshold:evt.thresholdID,
  agent:evt.agent,
  metric:evt.dataSource+'.'+evt.metric,
  msg:msg
 };

 logInfo("blocking " + evt.flowKey);
 logInfo("Info" + evt);
},['udp_reflection_attack']);

setIntervalHandler(function() {
  logInfo("Time");
 var now = Date.now();
 for(var key in controls) {
  let rec = controls[key];

  // keep control for at least 10 seconds
  if(now - rec.time < 10000) continue;
  // keep control if threshold still triggered
  if(thresholdTriggered(rec.threshold,rec.agent,rec.metric,key)) continue;


  delete controls[key];

  logInfo("unblocking " + key);
 }
});*/