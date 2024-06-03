var port = '0.0.0.0:8000'
var mapName = 'map_name'
var mapInfo = bpf.Map.list().find(i => i.name === mapName)

if (!mapInfo) throw `map '${mapName}' not found`

var map = bfp.Map.open(
  mapInfo.id,
  new CStruct({
    xaddr: 'uint8[4]',
    xport: 'uint16',
    l4proto: 'uint8',
    v6: 'uint8',
  }),
  new CStruct({
    daddr: 'uint8[4]',
    saddr: 'uint8[4]',
    sport: 'uint16',
    dport: 'uint16',
  })
)

var $target

pipy.listen(port, 'tcp', $=>$
  .onStart(i => findOriDst(i, 6))
  .pipe(() => $target ? 'pass' : 'deny', {
    'pass': $=>$.connect(() => $target),
    'deny': $=>$.replaceStreamStart(new StreamEnd),
  })
)

pipy.listen(port, 'udp', $=>$
  .onStart(i => findOriDst(i, 17))
  .pipe(() => $target ? 'pass' : 'deny', {
    'pass': $=>$.connect(() => $target, { protocol: 'udp' }),
    'deny': $=>$.replaceStreamStart(new StreamEnd),
  })
)

function findOriDst(inbound, proto) {
  var sip = new IP(inbound.remoteAddress)
  print(`${inbound.remoteAddress}:${inbound.remotePort} => `)
  var ent = map.lookup({
    xaddr: sip.toBytes(),
    xport: swap16(inbound.remotePort),
    l4proto: proto,
    v6: 0,
  })
  if (ent) {
    var ip = new IP(ent.daddr)
    var port = swap16(ent.dport)
    $target = `${ip}:${port}`
    println($target)
  } else {
    println('Not found')
  }
}

function swap16(n) {
  var l = 0x00ff & n
  var h = 0xff00 & n
  return (l << 8) | (h >> 8)
}

