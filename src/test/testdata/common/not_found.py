"""Test data to be used in test calls and assertions"""


# Response in the result_data objects data property for reputation actions
# when we pass a value not existing in RF
def testdata_reputation_wo_risk(entity, category):
    """Create result for entities wo known risk."""
    prefix = {
        'ip': 'ip:',
        'domain': 'idn:',
        'hash': 'hash:',
        'vulnerability': '',
        'url': 'url:'
    }[category]
    ctype = {
        'ip': u'IpAddress',
        'domain': u'InternetDomainName',
        'hash': 'Hash',
        'vulnerability': 'CyberVulnerability',
        'url': 'URL',
    }[category]
    rules_per_category = {
        'ip': 51,
        'domain': 22,
        'hash': 0,
        'vulnerability': 22,
        'url': 0,
    }[category]
    res = [
        {
            u'id': '%s%s' % (prefix, entity),
            u'name': u'%s' % entity,
            u'type': ctype,
            u'risklevel': 0,
            u'riskscore': 0,
            u'rulecount': 0,
            u'maxrules': rules_per_category,
            u'description': None,
            u'evidence': []
        }
    ]
    # currently only used for IP addresses vulnerability rules: 22, domain: 36

    return (
        res,
        u'Risklevel: 0.0, Type: IpAddress, Riskscore: 0.0'
    )

def testdata_reputation_na(entity, category):
    """Create result for entities that don't exist."""
    return (
        [
            {
                u'id': None,
                u'name': u'',
                u'type': None,
                u'risklevel': None,
                u'riskscore': None,
                u'rulecount': None,
                u'maxrules': None,
                u'description': u''
            }
        ],
        u'Riskscore: No information available.'
    )


# Response in the result_data object's data property for intelligence actions
# when we pass a value not existing in RF

# FILE
testdata_404_intelligence_file = {'data': [
    {
        'threatLists': [],
        'risk': {
            'riskSummary': 'No information available.',
            'criticality': None,
            'rules': None,
            'riskString': '',
            'score': None,
            'criticalityLabel': 'None',
            'evidenceDetails': []
        },
        'entity': {
            'name': '',
            'id': None,
            'type': None
        },
        'metrics': [],
        'intelCard': '',
        'timestamps': {
            'lastSeen': 'never',
            'firstSeen': 'never'
        },
        'relatedEntities': []
    }
],
    'message': 'Risksummary: No information available., '
               'Criticalitylabel: None, Lastseen: never'
}

# DOMAIN
testdata_404_intelligence_domain = testdata_404_intelligence_file

# URL
testdata_404_intelligence_url = {
    'data': [
        {
            'metrics': [],
            'timestamps': {
                'lastSeen': 'never',
                'firstSeen': 'never'
            },
            'relatedEntities': [],
            'risk': {
                'riskSummary': 'No information available.',
                'criticality': None,
                'rules': None,
                'riskString': '',
                'score': None,
                'criticalityLabel': 'None',
                'evidenceDetails': []
            },
            'entity': {
                'name': '',
                'id': None,
                'type': None
            }
        }
    ],

    'message': 'Risksummary: No information available., '
               'Criticalitylabel: None, Lastseen: never'
}

testdata_404_intelligence_vulnerability = {
    'data': [
        {
            'threatLists': [],
            'risk': {
                'riskSummary': 'No information available.',
                'criticality': None,
                'rules': None,
                'riskString': '',
                'score': None,
                'criticalityLabel': 'None',
                'evidenceDetails': []
            },
            'entity': {
                'name': '',
                'id': None,
                'type': None
            },
            'metrics': [],
            'intelCard': '',
            'timestamps': {
                'lastSeen': 'never',
                'firstSeen': 'never'
            },
            'relatedEntities': []
        }
    ],
    'message': 'Risksummary: No information available., '
               'Criticalitylabel: None, Lastseen: never'
}

testdata_404_intelligence_ip = {
    'data': [
        {
            'threatLists': [],
            'risk': {
                'riskSummary': 'No information available.',
                'criticality': None,
                'rules': None,
                'riskString': '',
                'score': None,
                'criticalityLabel': 'None',
                'evidenceDetails': []
            },
            'entity': {
                'name': '',
                'id': None,
                'type': None
            },
            'metrics': [],
            'intelCard': '',
            'location': {},
            'timestamps': {
                'lastSeen': 'never',
                'firstSeen': 'never'
            },
            'relatedEntities': []
        }
    ],
    'message': 'Risksummary: No information available., '
               'Criticalitylabel: None, Lastseen: never'
}
