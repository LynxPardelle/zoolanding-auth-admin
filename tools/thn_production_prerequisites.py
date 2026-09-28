"""Live, server-owned production state ledger. No TEST descriptor projection here.

The review operator supplies captured hashes after provisioning retained state.
Every protected activation re-reads those exact owners and the production row;
the fingerprint is sealed into the review baseline and checked before execute.
"""
from tools import thn_production_release as release
REQUIRED_OWNERS={
 'zoolanding-auth-admin-prod':{'ThnAuthAdminV2UserPool':'AWS::Cognito::UserPool','ThnAuthAdminV2CurrentUserStateTable':'AWS::DynamoDB::Table'},
 'zoolanding-content-hub-prod':{'ServiceBindingRegistryV2Table':'AWS::DynamoDB::Table','ThnContentHubV2MetadataTable':'AWS::DynamoDB::Table'},
 'zoolanding-image-upload':{'ThnPrivateUploadTransactionsV2Table':'AWS::DynamoDB::Table','ThnPrivateUploadV2Store':'AWS::S3::Bucket'},
}
def validate_selection(value,service,source_sha):
    release.require(isinstance(value,dict) and set(value)=={'schemaVersion','environment','service','sourceSha','owners','registrySha256'},'production_prerequisites_selection_missing')
    release.require(type(value['schemaVersion']) is int and value['schemaVersion']==1 and value['environment']=='production' and value['service']==service and value['sourceSha']==source_sha)
    release.require(isinstance(value['owners'],dict) and set(value['owners'])==set(REQUIRED_OWNERS))
    for proof in value['owners'].values():
        release.require(isinstance(proof,dict) and set(proof)=={'processedTemplateSha256','originalTemplateSha256','resourceInventorySha256'} and all(release._sha(v) for v in proof.values()))
    release.require(release._sha(value['registrySha256']))
    return value

def verify_registry(row):
    expected={'pk':'SERVICE_BINDING#production#thn-journal-production-v2','sk':'REGISTRY#V2','environment':'production','serviceBindingId':'thn-journal-production-v2','domain':'thehairnarrative.com','adminOrigin':'https://admin.thehairnarrative.com','cookieNamespace':'ltnafwb6videyraictgp','writerMode':'disabled'}
    release.require(isinstance(row,dict) and all(row.get(k)==v for k,v in expected.items()),'production_registry_must_be_isolated_and_closed')
    release.require(all(type(row.get(k)) is int and row[k]>=1 for k in ('registryRevision','writerEpoch')))
    return row

def capture(session,selection,service,source_sha):
    validate_selection(selection,service,source_sha)
    cf=session.client('cloudformation');owners={};native={}
    for name,required in REQUIRED_OWNERS.items():
        baseline=release.snapshot(cf,name)
        release.require(baseline['terminationProtection'] is True and baseline['status'] in {'CREATE_COMPLETE','UPDATE_COMPLETE','UPDATE_ROLLBACK_COMPLETE'})
        actual={'processedTemplateSha256':release.sha(release.parse_template(baseline['processed'])),
            'originalTemplateSha256':release.sha(release.parse_template(baseline['original'])),
            'resourceInventorySha256':release.sha(baseline['resources'])}
        release.require(actual==selection['owners'][name],'production_prerequisite_owner_changed')
        rows={r['LogicalResourceId']:r for r in baseline['resources']}
        for logical,kind in required.items():
            release.require(logical in rows and rows[logical]['ResourceType']==kind)
        owners[name]=actual;native[name]=rows
    pool=native['zoolanding-auth-admin-prod']['ThnAuthAdminV2UserPool']['PhysicalResourceId']
    client=session.client('cognito-idp')
    config=client.describe_user_pool(UserPoolId=pool)['UserPool']
    release.require(config.get('Name')=='zoolanding-auth-admin-prod-ThnAuthAdminV2' and config.get('MfaConfiguration')=='ON' and config.get('DeletionProtection')=='ACTIVE' and config.get('AdminCreateUserConfig',{}).get('AllowAdminCreateUserOnly') is True)
    mfa=client.get_user_pool_mfa_config(UserPoolId=pool)
    release.require(mfa.get('MfaConfiguration')=='ON' and mfa.get('SoftwareTokenMfaConfiguration',{}).get('Enabled') is True)
    from boto3.dynamodb.types import TypeDeserializer
    table=native['zoolanding-content-hub-prod']['ServiceBindingRegistryV2Table']['PhysicalResourceId']
    release.require(table=='zoolanding-content-hub-prod-ServiceBindingRegistryV2')
    item=session.client('dynamodb').get_item(TableName=table,Key={'pk':{'S':'SERVICE_BINDING#production#thn-journal-production-v2'},'sk':{'S':'REGISTRY#V2'}},ConsistentRead=True).get('Item')
    release.require(isinstance(item,dict) and item,'production_registry_prerequisite_missing')
    row={key:TypeDeserializer().deserialize(value) for key,value in item.items()}
    # DynamoDB numeric schema counters are integers, never decimal strings.
    for key in ('registryRevision','writerEpoch'):
        from decimal import Decimal
        if isinstance(row.get(key),Decimal) and row[key]==int(row[key]):row[key]=int(row[key])
    verify_registry(row)
    release.require(release.sha(row)==selection['registrySha256'],'production_registry_prerequisite_changed')
    return {'owners':owners,'registrySha256':release.sha(row),'poolConfigurationSha256':release.sha(config),'mfaConfigurationSha256':release.sha(mfa)}
