import boto3

def reset_dashboard():
    dynamodb = boto3.resource('dynamodb', region_name="us-east-2")
    table = dynamodb.Table('SentinelMonitor')
    
    print("🧹 Iniciando limpeza da tabela...")
    
    # Busca todos os itens (apenas as chaves para ser rápido)
    scan = table.scan(ProjectionExpression='id_recurso')
    items = scan.get('Items', [])
    
    if not items:
        print("✅ A tabela já está vazia.")
        return

    # Apaga item por item
    with table.batch_writer() as batch:
        for item in items:
            batch.delete_item(Key={'id_recurso': item['id_recurso']})
            
    print(f"🚀 Sucesso! {len(items)} registros removidos. Dashboard zerado.")

if __name__ == "__main__":
    reset_dashboard()