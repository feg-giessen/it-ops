syslog-ng configuration
======

## Juniper SRX Router (JunOS) ##

 - Write Juniper SRX syslog messages to different files
 - Parse `RT_FLOW` messages and write fields to MySQL table

`rt_flow_sessions.xml` is based on [RobWC/syslog-ng-SRX](https://github.com/RobWC/syslog-ng-SRX/blob/master/baseline-pattern.xml)

## Template for Switch Configuration ##

    python generate-switch-conf.py
