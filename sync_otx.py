from CORE.otx_ingestion import ingest_otx_feed
if __name__=="__main__":
    try:
        r=ingest_otx_feed(10)
        print("AlienVault OTX feed synchronization completed.")
        print("Valid indicators fetched:",r["fetched"])
        print("New IOCs inserted:",r["inserted"])
    except Exception as e:
        print("OTX feed synchronization failed:",e)
