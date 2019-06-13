"""Test data to be used in test calls and assertions"""

# Response in the result_data objects data property for reputation actions
# when we pass a value not existing in RF
testdata_404_reputation = {
    'data': [
        {
            u'risk': {
                u'score': None,
                u'rule': {
                    u'maxCount': None,
                    u'count': None
                },
                u'level': None
            },
            u'entity': {
                u'name': u''
            }
        }
    ],
    'message': u'Score: None, Type: None, Level: None'
}

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
            'name': ''
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
                'name': ''
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
                'name': ''
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
                'name': ''
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
