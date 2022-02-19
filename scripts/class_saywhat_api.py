#!/usr/bin/python
# -*- coding: utf-8 -*-
from swpag_client import Team
teamToken = 'S4f8RdeFHFvQ6ZszSDTU'
gameIp = 'http://52.37.204.0'
class ProjectCTFAPI:
    # This is just a simple wrapper class
    # See client.py for more methods supported by self.team
    __slots__ = ('team', 'debug')
    def __init__(self):
        self.debug = False
        self.team = Team(gameIp, teamToken)
    def getServices(self):
        ids = []
        services = self.team.get_service_list()
        if self.debug:
            print('~' * 5 + ' Service List ' + '~' * 5)
        for s in services:
            ids.append(s['service_id'])
            if self.debug:
                print("Service %s: %s\n\t'%s'" % (s['service_id'],s['service_name'], s['description']))
        return ids
    def getTargets(self, service):
        targets = self.team.get_targets(service)
        if self.debug:
            print('~' * 5 + ' Targets for service %s ' % service + '~'  \
            * 5)
            for t in targets:
                for key in ['hostname', 'port', 'flag_id', 'team_name']:
                    print('%10s : %s' % (key, t[key]))
                print('\n')
        return targets
    def submitFlag(self, oneOrMoreFlags):
        if not isinstance(oneOrMoreFlags, list):
            oneOrMoreFlags = [oneOrMoreFlags]
        status = self.team.submit_flag(oneOrMoreFlags)
        if self.debug:
            for (i, s) in enumerate(status):
                print('Flag %s submission status: %s' \
                    % (oneOrMoreFlags[i], s))
        return status