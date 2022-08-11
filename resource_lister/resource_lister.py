from datetime import datetime, timedelta, timezone
# Importazione delle classi specifiche per servizio
from cw_services.cw_elb import CloudWatchELB, CloudWatchELBTG
from cw_services.cw_ec2 import CloudWatchEC2
from cw_services.cw_ebs import CloudWatchEBS
from cw_services.cw_efs import CloudWatchEFS
from cw_services.cw_rds import CloudWatchRDS
from cw_services.cw_eks import CloudWatchEKS
from cw_services.cw_vpn import CloudWatchVPN
from cw_services.cw_os import CloudWatchOS
from cw_services.cw_acm import CloudWatchACM


class ResourceLister:
    def __init__(self, cloudwatchclient, filter_tag_key, filter_tag_value):
        self.cloudwatchclient = cloudwatchclient
        self.filter_tag_key = filter_tag_key
        self.filter_tag_value = filter_tag_value

    # Estrazione lista EC2 con tag predefinito
    def list_ec2(self, client, default_values):
        print(f"start list_ec2 {datetime.now()}")
        instances_list = []

        next_token = ""
        while next_token is not None:
            ec2_resp = client.describe_instances(
                NextToken=next_token,
                Filters=[{"Name": "tag:" + self.filter_tag_key, "Values": [self.filter_tag_value]},
                         {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
            next_token = ec2_resp.get("NextToken", None)

            for reservation in ec2_resp["Reservations"]:
                instances_list.extend(reservation["Instances"])

        print(f"end list_ec2 {datetime.now()}")
        for ec2 in instances_list:
            CloudWatchEC2(ec2, self.cloudwatchclient, default_values)

    
    # Estrazione lista RDS con tag predefinito
    def list_rds(self, client, default_values):
        print(f"start list_rds {datetime.now()}")
        # Estrazione elenco istanze
        databasesinstances = []
        paginator = client.get_paginator("describe_db_instances")
        pages = paginator.paginate()
        for page in pages:
            databasesinstances.extend(page["DBInstances"])

        # Estrazione elenco cluster
        databasesclusters = []
        paginator = client.get_paginator("describe_db_clusters")
        pages = paginator.paginate()
        for page in pages:
            databasesclusters.extend(page["DBClusters"])

        database_list = []
        # Verifica istanze con tag da filtrare tra quelli estratti
        for database in databasesinstances:
            for tag in database["TagList"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    database_list.append(database)
        # Verifica cluster con tag da filtrare tra quelli estratti
        for database in databasesclusters:
            for tag in database["TagList"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    database_list.append(database)

        print(f"end list_rds {datetime.now()}")
        for rds in database_list:
            CloudWatchRDS(rds, self.cloudwatchclient, default_values)

    
    # Estrazione lista EFS con tag predefinito
    def list_efs(self, client, default_values):
        print(f"start list_efs {datetime.now()}")
        # Estrazione elenco filesystem
        filesystems = []  # client.describe_file_systems()
        paginator = client.get_paginator("describe_file_systems")
        pages = paginator.paginate()
        for page in pages:
            filesystems.extend(page["FileSystems"])

        filesystem_list = []
        # Verifica istanze con tag da filtrare tra quelli estratti
        for filesystem in filesystems:
            for tag in filesystem["Tags"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    filesystem_list.append(filesystem)
        print(f"end list_efs {datetime.now()}")
        for efs in filesystem_list:
            CloudWatchEFS(efs, self.cloudwatchclient, default_values)

    
    # Estrazione lista ALB con tag predefinito
    def list_elb(self, client, default_values_alb, default_values_nlb):
        print(f"start list_elb {datetime.now()}")
        # Estrazione elenco bilanciatori
        loadbalancers = []
        next_marker = ""
        while next_marker is not None:
            elb_resp = client.describe_load_balancers(Marker=next_marker)
            next_marker = elb_resp.get("NextMarker", None)
            loadbalancers.extend(elb_resp["LoadBalancers"])

        alb_list = []
        nlb_list = []

        # Verifica bilanciatori con tag da filtrare tra quelli estratti
        if len(loadbalancers) > 0:
            tags = client.describe_tags(
                ResourceArns=[loadbalancer["LoadBalancerArn"] for loadbalancer in loadbalancers])["TagDescriptions"]
        for loadbalancer in loadbalancers:
            # Si tiene traccia della posizione del tagset così che lo si possa cancellare dai tag
            index_lb_tag = -1
            for index, taglist in enumerate(tags):
                if taglist["ResourceArn"] == loadbalancer["LoadBalancerArn"]:
                    index_lb_tag = index
                    break

            if index_lb_tag > -1:
                for tag in tags[index_lb_tag]["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        # Aggiungo al loadbalancer tutti i suoi tag. Serve siccome nell"init di CloudWatchALB si usano
                        # anche i tag per stabilire il nome del ci
                        loadbalancer["Tags"] = taglist["Tags"]

                        if loadbalancer["Type"] == "application":
                            alb_list.append(loadbalancer)
                        elif loadbalancer["Type"] == "network":
                            nlb_list.append(loadbalancer)
                        elif loadbalancer["Type"] == "gateway":
                            pass

                        break
                tags.pop(index_lb_tag)
        print(f"end list_elb {datetime.now()}")
        for alb in alb_list:
            CloudWatchELB(alb, self.cloudwatchclient, default_values_alb)
        for nlb in nlb_list:
            CloudWatchELB(nlb, self.cloudwatchclient, default_values_nlb)

    
    # Estrazione lista Target Groups (sia per gli ALB che per gli NLB) con tag predefinito
    def list_elbtg(self, client, default_values_albtg, default_values_nlbtg):
        print(f"start list_elbtg {datetime.now()}")
        # Recupero i tag del target group così da estrarne il nome
        # Mappa elbarn: [tg_con_quell_arn, ...]
        targetgroups_elbs_arn = {}
        next_marker = ""
        while next_marker is not None:
            tg_resp = client.describe_target_groups(
                Marker=next_marker)
            next_marker = tg_resp.get("NextMarker", None)

            for tg in tg_resp["TargetGroups"]:
                # Controllo se il tg ha un bilanciatore associato
                if len(tg["LoadBalancerArns"]) > 0:
                    elb_arn = tg["LoadBalancerArns"][0]
                    if elb_arn not in targetgroups_elbs_arn:
                        targetgroups_elbs_arn[elb_arn] = []

                    targetgroups_elbs_arn[elb_arn].append(tg)

        # Verifico i tg in base al tipo dell"elb associato
        client.describe_load_balancers(
            LoadBalancerArns=list(targetgroups_elbs_arn.keys()))
        loadbalancers = []
        next_marker = ""
        while next_marker is not None:
            elb_resp = client.describe_load_balancers(Marker=next_marker)
            next_marker = elb_resp.get("NextMarker", None)

            for elb in elb_resp["LoadBalancers"]:
                if elb["Type"] in ["application", "network"]:
                    # Assegno ad ogni tg la tipologia del bilanciatore a cui sono associati
                    for tg in targetgroups_elbs_arn[elb["LoadBalancerArn"]]:
                        tg["ELBType"] = elb["Type"]
                elif elb["Type"] in ["gateway"]:
                    # Rimuovo dalla mappa di elbarn: [pos_tg_con_quell_arn, ...] gli arn dei bilanciatori che non sono dell"array nell'if
                    del targetgroups_elbs_arn[elb["LoadBalancerArn"]]

            loadbalancers.extend(elb_resp["LoadBalancers"])

        # Costruisco un array unico con tutti i tg
        targetgroups = []
        for key in targetgroups_elbs_arn:
            targetgroups.extend(targetgroups_elbs_arn[key])

        # Scarico i tag dei vari tg
        targetgroups_arn = []
        for tg in targetgroups:
            targetgroups_arn.append(tg["TargetGroupArn"])

        # Verifico che abbiano il tag per monitorarli
        if len(targetgroups_arn) > 0:
            targetgroups_tags = client.describe_tags(
                ResourceArns=targetgroups_arn)["TagDescriptions"]

        for tg in targetgroups:
            index_tg_tag = -1
            for index, taglist in enumerate(targetgroups_tags):
                has_tag = False
                for tag in taglist["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        has_tag = True

                # Non c"è il tag che definisce di monitorare le risorse
                if not has_tag:
                    break

                # Si tiene traccia della posizione del tag così che lo si possa cancellare dai tag
                if taglist["ResourceArn"] == tg["TargetGroupArn"]:
                    index_tg_tag = index
                    break

            if index_tg_tag > -1:
                tg["Tags"] = targetgroups_tags[index_tg_tag]["Tags"]

                if tg["ELBType"] == "application":
                    CloudWatchELBTG(tg, self.cloudwatchclient, default_values_albtg)
                elif tg["ELBType"] == "network":
                    CloudWatchELBTG(tg, self.cloudwatchclient, default_values_nlbtg)
                targetgroups_tags.pop(index_tg_tag)
        print(f"end list_elbtg {datetime.now()}")

    
    def list_ebs(self, client, default_values):
        print(f"start list_ebs {datetime.now()}")
        tmp_volumes = []
        next_token = ""
        while next_token is not None:
            ebs_resp = client.describe_volumes(
                NextToken=next_token,
                Filters=[{"Name": "tag:" + self.filter_tag_key, "Values": [self.filter_tag_value]},
                         {"Name": "status", "Values": ["in-use"]}])
            next_token = ebs_resp.get("NextToken", None)
            tmp_volumes.extend(ebs_resp["Volumes"])

        volumes_list = []
        for vol in tmp_volumes:
            # Filtra solo i dischi creati almeno da 30 minuti
            date_to_compare = (vol["CreateTime"].replace(
                tzinfo=timezone.utc) + timedelta(minutes=30))
            my_date = datetime.now(timezone.utc)
            if date_to_compare < my_date:
                for attachment in vol["Attachments"]:
                    if attachment["State"] == "attached":
                        ec2_tags = client.describe_instances(
                            InstanceIds=[attachment["InstanceId"]])["Reservations"][0]["Instances"][0]["Tags"]
                        ec2_name = ""
                        for tag in ec2_tags:
                            if tag["Key"] == "Name":
                                ec2_name = tag["Value"]
                                break
                        break
                vol["EC2Name"] = ec2_name
                volumes_list.append(vol)

        print(f"end list_ebs {datetime.now()}")
        for ebs in volumes_list:
            CloudWatchEBS(ebs, self.cloudwatchclient, default_values)

    
    def list_eks(self, client, default_values):
        print(f"start list_eks {datetime.now()}")
        clusters = []
        next_token = ""
        while next_token is not None:
            eks_resp = client.list_clusters(nextToken=next_token)
            next_token = eks_resp.get("nextToken", None)
            clusters.extend(eks_resp["clusters"])

        cluster_list = []
        for cluster in clusters:
            local_cluster = client.describe_cluster(name=cluster)["cluster"]
            if local_cluster is not None:
                tags = local_cluster["tags"]
                if tags.get(self.filter_tag_key, "no") == self.filter_tag_value:
                    cluster_list.append(local_cluster)
        print(f"end list_eks {datetime.now()}")
        for eks in cluster_list:
            CloudWatchEKS(eks, self.cloudwatchclient, default_values)

    
    def list_vpn(self, client, default_values):
        print(f"start list_vpn {datetime.now()}")
        vpn_list = []

        vpn_connections = client.describe_vpn_connections()["VpnConnections"]
        for vpn in vpn_connections:
            for tag in vpn["Tags"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    vpn_list.append(vpn)
                    break

        print(f"end list_vpn {datetime.now()}")
        for vpn in vpn_list:
            CloudWatchVPN(vpn, self.cloudwatchclient, default_values)

    
    def list_acm(self, client, default_values):
        print(f"start list acm {datetime.now()}")
        certificates_list = []
        renewal_eligibility_status = "INELIGIBLE"

        # Scarico il primo blocco di certificati (non è possibile mettere tutto in un unico while siccome il metodo list_certificates non accetta NextToken come stringa vuota)
        certificates_resp = client.list_certificates()
        next_token = certificates_resp.get("NextToken", None)
        for ca in certificates_resp["CertificateSummaryList"]:
            cert_detail = client.describe_certificate(
                CertificateArn=ca["CertificateArn"])["Certificate"]

            if cert_detail.get("RenewalEligibility", "") == renewal_eligibility_status:
                ca_tags = client.list_tags_for_certificate(
                    CertificateArn=ca["CertificateArn"])["Tags"]
                for tag in ca_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        certificates_list.append(ca)
                        break

        # Scarico eventuali nuovi certificati
        while next_token is not None:
            certificates_resp = client.list_certificates(NextToken=next_token)
            next_token = certificates_resp.get("NextToken", None)

            for ca in certificates_resp["CertificateSummaryList"]:
                cert_detail = client.describe_certificate(
                    CertificateArn=ca["CertificateArn"])["Certificate"]

                if cert_detail.get("RenewalEligibility", "") == renewal_eligibility_status:
                    ca_tags = client.list_tags_for_certificate(
                        CertificateArn=ca["CertificateArn"])["Tags"]
                    for tag in ca_tags:
                        if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                            certificates_list.append(ca)
                            break

        print(f"end list acm {datetime.now()}")
        for acm in certificates_list:
            CloudWatchACM(acm, self.cloudwatchclient, default_values)

    
    def list_os(self, client, default_values):
        print(f"start list_os {datetime.now()}")
        domains_list = []

        os_names = client.list_domain_names()["DomainNames"]

        for os in os_names:
            os_details = client.describe_domain(
                DomainName=os["DomainName"])["DomainStatus"]
            if os_details is not None:
                os_tags = client.list_tags(ARN=os_details["ARN"])["TagList"]
                for tag in os_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        domains_list.append(os_details)
                        break
        print(f"end list_os {datetime.now()}")
        for os in domains_list:
            CloudWatchOS(os, self.cloudwatchclient, default_values)
