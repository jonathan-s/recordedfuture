"""Test data to be used in test calls and assertions"""

# Response in the result_data objects data property for reputation actions
# when we pass a value not existing in RF
testdata_404_reputation = {'data' : [
                          {
                              'timestamps': {
                                  'lastSeen': 'never',
                                  'firstSeen': 'never'
                              },
                              'risk': {
                                  'riskSummary': 'No Risk Rules are currently observed.',
                                  'criticality': 0,
                                  'rules': 0,
                                  'riskString': '',
                                  'score': 0,
                                  'criticalityLabel': 'None',
                                  'evidenceDetails': []
                              },
                              'entity': {
                                  'name': ''
                              }
                          }
                      ],
    'message': 'Risksummary: No Risk Rules are currently observed., Criticalitylabel: None, Lastseen: never'
}

# Response in the result_data object's data property for intelligence actions
# when we pass a value not existing in RF

# FILE
testdata_404_intelligence_file = {'data': [
    {
        'threatLists': [],
        'risk': {
            'riskSummary': 'No Risk Rules are currently observed.',
            'criticality': 0,
            'rules': 0,
            'riskString': '',
            'score': 0,
            'criticalityLabel': 'None',
            'evidenceDetails': []
        },
        'entity': {
            'name': ''
        },
        'metrics': [
            {
                'type': 'pasteHits',
                'value': 0
            },
            {
                'type': 'darkWebHits',
                'value': 0
            },
            {
                'type': 'criticality',
                'value': 0
            },
            {
                'type': 'undergroundForumHits',
                'value': 0
            },
            {
                'type': 'maliciousHits',
                'value': 0
            },
            {
                'type': 'technicalReportingHits',
                'value': 0
            },
            {
                'type': 'infoSecHits',
                'value': 0
            },
            {
                'type': 'totalHits',
                'value': 0
            },
            {
                'type': 'sixtyDaysHits',
                'value': 0
            },
            {
                'type': 'oneDayHits',
                'value': 0
            },
            {
                'type': 'socialMediaHits',
                'value': 0
            },
            {
                'type': 'sevenDaysHits',
                'value': 0
            }
        ],
        'intelCard': '',
        'timestamps': {
            'lastSeen': 'never',
            'firstSeen': 'never'
        },
        'relatedEntities': []
    }
],
    'message': 'Risksummary: No Risk Rules are currently observed., Criticalitylabel: None, Lastseen: never'
}

# DOMAIN
testdata_404_intelligence_domain = testdata_404_intelligence_file

# URL
testdata_404_intelligence_url = {
    'data': [
                        {
                            'metrics': [
                                {
                                    'type': 'pasteHits',
                                    'value': 0
                                },
                                {
                                    'type': 'darkWebHits',
                                    'value': 0
                                },
                                {
                                    'type': 'criticality',
                                    'value': 0
                                },
                                {
                                    'type': 'undergroundForumHits',
                                    'value': 0
                                },
                                {
                                    'type': 'maliciousHits',
                                    'value': 0
                                },
                                {
                                    'type': 'technicalReportingHits',
                                    'value': 0
                                },
                                {
                                    'type': 'infoSecHits',
                                    'value': 0
                                },
                                {
                                    'type': 'totalHits',
                                    'value': 0
                                },
                                {
                                    'type': 'sixtyDaysHits',
                                    'value': 0
                                },
                                {
                                    'type': 'oneDayHits',
                                    'value': 0
                                },
                                {
                                    'type': 'socialMediaHits',
                                    'value': 0
                                },
                                {
                                    'type': 'sevenDaysHits',
                                    'value': 0
                                }
                            ],
                            'timestamps': {
                                'lastSeen': 'never',
                                'firstSeen': 'never'
                            },
                            'relatedEntities': [],
                            'risk': {
                                'riskSummary': 'No Risk Rules are currently observed.',
                                'criticality': 0,
                                'rules': 0,
                                'riskString': '',
                                'score': 0,
                                'criticalityLabel': 'None',
                                'evidenceDetails': []
                            },
                            'entity': {
                                'name': ''
                            }
                        }
                    ],

        'message': 'Risksummary: No Risk Rules are currently observed., Criticalitylabel: None, Lastseen: never'
}

testdata_404_intelligence_vulnerability = {
    'data': [
        {
            'threatLists': [],
            'risk': {
                'riskSummary': 'No Risk Rules are currently observed.',
                'criticality': 0,
                'rules': 0,
                'riskString': '',
                'score': 0,
                'criticalityLabel': 'None',
                'evidenceDetails': []
            },
            'entity': {
                'name': ''
            },
            'metrics': [
                {
                    'type': 'pasteHits',
                    'value': 0
                },
                {
                    'type': 'darkWebHits',
                    'value': 0
                },
                {
                    'type': 'criticality',
                    'value': 0
                },
                {
                    'type': 'undergroundForumHits',
                    'value': 0
                },
                {
                    'type': 'maliciousHits',
                    'value': 0
                },
                {
                    'type': 'technicalReportingHits',
                    'value': 0
                },
                {
                    'type': 'infoSecHits',
                    'value': 0
                },
                {
                    'type': 'totalHits',
                    'value': 0
                },
                {
                    'type': 'sixtyDaysHits',
                    'value': 0
                },
                {
                    'type': 'oneDayHits',
                    'value': 0
                },
                {
                    'type': 'socialMediaHits',
                    'value': 0
                },
                {
                    'type': 'sevenDaysHits',
                    'value': 0
                }
            ],
            'intelCard': '',
            'timestamps': {
                'lastSeen': 'never',
                'firstSeen': 'never'
            },
            'relatedEntities': []
        }
    ],
    'message': 'Risksummary: No Risk Rules are currently observed., Criticalitylabel: None, Lastseen: never'
}

testdata_404_intelligence_ip = {
    'data': [
        {
            'threatLists': [],
            'risk': {
                'riskSummary': 'No Risk Rules are currently observed.',
                'criticality': 0,
                'rules': 0,
                'riskString': '',
                'score': 0,
                'criticalityLabel': 'None',
                'evidenceDetails': []
            },
            'entity': {
                'name': ''
            },
            'metrics': [
                {
                    'type': 'pasteHits',
                    'value': 0
                },
                {
                    'type': 'darkWebHits',
                    'value': 0
                },
                {
                    'type': 'criticality',
                    'value': 0
                },
                {
                    'type': 'undergroundForumHits',
                    'value': 0
                },
                {
                    'type': 'maliciousHits',
                    'value': 0
                },
                {
                    'type': 'technicalReportingHits',
                    'value': 0
                },
                {
                    'type': 'infoSecHits',
                    'value': 0
                },
                {
                    'type': 'totalHits',
                    'value': 0
                },
                {
                    'type': 'sixtyDaysHits',
                    'value': 0
                },
                {
                    'type': 'oneDayHits',
                    'value': 0
                },
                {
                    'type': 'socialMediaHits',
                    'value': 0
                },
                {
                    'type': 'sevenDaysHits',
                    'value': 0
                }
            ],
            'intelCard': '',
            'location': {},
            'timestamps': {
                'lastSeen': 'never',
                'firstSeen': 'never'
            },
            'relatedEntities': []
        }
    ],
    'message': 'Risksummary: No Risk Rules are currently observed., Criticalitylabel: None, Lastseen: never'
}
