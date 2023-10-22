import asyncio
import pickle

from loguru import logger
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp, udp6
from pysnmp.entity.rfc3413 import ntfrcv
import uuid6


logger.add("app.log", format="{level} : {time} : {message}: {process}")

bindIF = "0.0.0.0"


def requestObserver(snmpEngine, execpoint, variables, cbCtx):
    packet = "Execution point: %s" % execpoint + \
        "* transportDomain: %s" % ".".join([str(x) for x in variables["transportDomain"]]) + \
        "* transportAddress: %s" % "@".join([str(x) for x in variables['transportAddress']]) + \
        "* securityModel: %s" % variables['securityModel'] + \
        "* securityName: %s" % variables['securityName'] + \
        "* securityLevel: %s" % variables['securityLevel'] + \
        "* contextEngineId: %s" % variables['contextEngineId'].prettyPrint() + \
        "* contextName: %s" % variables['contextName'].prettyPrint() + \
        "* PDU: %s" % variables['pdu'].prettyPrint()
    logger.info(packet)


def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    logger.info('Notify from ContextId "%s", ContextName "%s"' % (contextEngineId.prettyPrint(),
                                                            contextName.prettyPrint()))
    uuid = uuid6.uuid7()
    filename = f"{uuid}-snmptrap.pickle"
    try:
        # JSON形式でファイルに出力
        with open(filename, 'wb') as f:
            pickle.dump(varBinds, f, protocol=5)

    except TypeError as e:
        # JSON形式で保存できない場合はpickleを使用
        logger.exception(e)

    # for name, val in varBinds:
    #    logger.info('%s = %s' % (name.prettyPrint(), val.prettyPrint()))

    # 対応するコマンドを起動する
    cmd = f"/bin/ls {filename}"
    asyncio.run(run(cmd))


async def run(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    stdout, stderr = await proc.communicate()

    logger.info(f'[{cmd!r} exited with {proc.returncode}]')
    if stdout:
        logger.info(f"{stdout.decode()}")
    if stderr:
        logger.error(f"{stderr.decode()}")


def main():
    snmpEngine = engine.SnmpEngine()

    # for receive logging
    snmpEngine.observer.registerObserver(
        requestObserver,
        'rfc3412.receiveMessage:request',
        'rfc3412.returnResponsePdu'
    )

    # port: 162 receive
    config.addTransport(
        snmpEngine,
        udp.domainName,
        udp.UdpTransport().openServerMode((bindIF, 162))
    )

    # IPv6 bind
    # config.addTransport(
    #     snmpEngine,
    #     udp6.domainName,
    #     udp6.Udp6Transport().openServerMode((bindIF, 162))
    # )

    # SNMP v1 my-area is security name
    config.addV1System(snmpEngine, 'my-area', 'public')

    ntfrcv.NotificationReceiver(snmpEngine, cbFun)        

    # not return   
    snmpEngine.transportDispatcher.jobStarted(1)
        
    try:
        snmpEngine.transportDispatcher.runDispatcher()
    except Exception as e:
        logger.exception(e)
        snmpEngine.observer.unregisterObserver()
        snmpEngine.transportDispatcher.closeDispatcher()
    
    logger.info("recv ending")


if __name__ == "__main__":
    main()