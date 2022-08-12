from datetime import datetime, timedelta, timezone


class ResourceLister:
    def __init__(self, filter_tag_key, filter_tag_value):
        self.filter_tag_key = filter_tag_key
        self.filter_tag_value = filter_tag_value

    def list_acm(self, client, filters, callback, callback_params):
        print(f"start list acm {datetime.now()}")
        certificates_list = []
        renewal_eligibility_status = "INELIGIBLE"

        # Download first block of certificattes
        # It is not possible use a single while because list_certificates method does not accept NextToken as empty string
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

        # Download other certificates if available
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
        if callback:
            callback(certificates_list, *callback_params)

    def list_ebs(self, client, filters, callback, callback_params):
        print(f"start list_ebs {datetime.now()}")
        tmp_volumes = []
        next_token = ""
        while next_token is not None:
            ebs_resp = client.describe_volumes(
                NextToken=next_token,
                Filters=filters)
            next_token = ebs_resp.get("NextToken", None)
            tmp_volumes.extend(ebs_resp["Volumes"])

        volumes_list = []
        for vol in tmp_volumes:
            # Filters only disks that have been created for at least 30 minutes
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
        if callback:
            callback(volumes_list, *callback_params)

    def list_ec2(self, client, filters, callback, callback_params):
        print(f"start list_ec2 {datetime.now()}")
        instances_list = []

        next_token = ""
        while next_token is not None:
            ec2_resp = client.describe_instances(
                NextToken=next_token,
                Filters=filters)
            next_token = ec2_resp.get("NextToken", None)

            for reservation in ec2_resp["Reservations"]:
                instances_list.extend(reservation["Instances"])

        print(f"end list_ec2 {datetime.now()}")
        if callback:
            callback(instances_list, *callback_params)

    def list_efs(self, client, filters, callback, callback_params):
        print(f"start list_efs {datetime.now()}")
        filesystems = []
        paginator = client.get_paginator("describe_file_systems")
        pages = paginator.paginate()
        for page in pages:
            filesystems.extend(page["FileSystems"])

        filesystem_list = []
        
        # Filter instance by tags
        for filesystem in filesystems:
            for tag in filesystem["Tags"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    filesystem_list.append(filesystem)
        print(f"end list_efs {datetime.now()}")
        if callback:
            callback(filesystem_list, *callback_params)

    def list_eks(self, client, filters, callback, callback_params):
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
        if callback:
            callback(cluster_list, *callback_params)

    def list_elb(self, client, filters, callback, callback_params):
        print(f"start list_elb {datetime.now()}")
        loadbalancers = []
        next_marker = ""
        while next_marker is not None:
            elb_resp = client.describe_load_balancers(Marker=next_marker)
            next_marker = elb_resp.get("NextMarker", None)
            loadbalancers.extend(elb_resp["LoadBalancers"])

        alb_list = []
        nlb_list = []

        # Filter elb by tags
        if len(loadbalancers) > 0:
            tags = client.describe_tags(
                ResourceArns=[loadbalancer["LoadBalancerArn"] for loadbalancer in loadbalancers])["TagDescriptions"]
        for loadbalancer in loadbalancers:
            # Keep track of the location of the tagset so that you can delete it from the tags
            index_lb_tag = -1
            for index, taglist in enumerate(tags):
                if taglist["ResourceArn"] == loadbalancer["LoadBalancerArn"]:
                    index_lb_tag = index
                    break

            if index_lb_tag > -1:
                for tag in tags[index_lb_tag]["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        # We add to the loadbalancer all its tags. It is needed since in the init of CloudWatchALB we use
                        # also tags to establish the name of the ci
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
        if callback:
            callback(alb_list, nlb_list, *callback_params)

    
    def list_elbtg(self, client, filters, callback, callback_params):
        print(f"start list_elbtg {datetime.now()}")
        # I retrieve the tags of the target group so I can extract its name
        # elbarn: [tg_with_that_arn, ...]
        targetgroups_elbs_arn = {}
        next_marker = ""
        while next_marker is not None:
            tg_resp = client.describe_target_groups(
                Marker=next_marker)
            next_marker = tg_resp.get("NextMarker", None)

            for tg in tg_resp["TargetGroups"]:
                # Checks whether the target group has an associated balancer
                if len(tg["LoadBalancerArns"]) > 0:
                    elb_arn = tg["LoadBalancerArns"][0]
                    if elb_arn not in targetgroups_elbs_arn:
                        targetgroups_elbs_arn[elb_arn] = []

                    targetgroups_elbs_arn[elb_arn].append(tg)

        # Verify the target groups based on the type of the associated elb
        client.describe_load_balancers(
            LoadBalancerArns=list(targetgroups_elbs_arn.keys()))
        loadbalancers = []
        next_marker = ""
        while next_marker is not None:
            elb_resp = client.describe_load_balancers(Marker=next_marker)
            next_marker = elb_resp.get("NextMarker", None)

            for elb in elb_resp["LoadBalancers"]:
                if elb["Type"] in ["application", "network"]:
                    # I assign to each tg the type of balancer with which they are associated
                    for tg in targetgroups_elbs_arn[elb["LoadBalancerArn"]]:
                        tg["ELBType"] = elb["Type"]
                elif elb["Type"] in ["gateway"]:
                    # Remove from elbarn map: [pos_tg_with_that_arn, ...] arn of balancers not in the list
                    del targetgroups_elbs_arn[elb["LoadBalancerArn"]]

            loadbalancers.extend(elb_resp["LoadBalancers"])

        # Create unique array with all tgs
        targetgroups = []
        for key in targetgroups_elbs_arn:
            targetgroups.extend(targetgroups_elbs_arn[key])

        # Download tags of all tgs
        targetgroups_arn = []
        for tg in targetgroups:
            targetgroups_arn.append(tg["TargetGroupArn"])

        # Check if tgs have the tag to monitor them
        targetgroups_tags = []
        if len(targetgroups_arn) > 0:
            targetgroups_tags = client.describe_tags(
                ResourceArns=targetgroups_arn)["TagDescriptions"]

        alb_tg_list = []
        nlb_tg_list = []
        for tg in targetgroups:
            index_tg_tag = -1
            for index, taglist in enumerate(targetgroups_tags):
                has_tag = False
                for tag in taglist["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        has_tag = True

                # There is no tag that defines to monitor resources
                if not has_tag:
                    break

                # Keep track of the location of the tag so it can be deleted from the tags
                if taglist["ResourceArn"] == tg["TargetGroupArn"]:
                    index_tg_tag = index
                    break

            if index_tg_tag > -1:
                tg["Tags"] = targetgroups_tags[index_tg_tag]["Tags"]

                if tg["ELBType"] == "application":
                    alb_tg_list.append(tg)
                elif tg["ELBType"] == "network":
                    nlb_tg_list.append(tg)
                targetgroups_tags.pop(index_tg_tag)
        if callback:
            callback(alb_tg_list, nlb_tg_list, targetgroups_tags, *callback_params)
        print(f"end list_elbtg {datetime.now()}")

    def list_os(self, client, filters, callback, callback_params):
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
        if callback:
            callback(domains_list, *callback_params)

    
    def list_rds(self, client, filters, callback, callback_params):
        print(f"start list_rds {datetime.now()}")
        # Instance list extraction
        databasesinstances = []
        paginator = client.get_paginator("describe_db_instances")
        pages = paginator.paginate()
        for page in pages:
            databasesinstances.extend(page["DBInstances"])

        # Cluster list extraction
        databasesclusters = []
        paginator = client.get_paginator("describe_db_clusters")
        pages = paginator.paginate()
        for page in pages:
            databasesclusters.extend(page["DBClusters"])

        database_list = []
        # Verify instances with tags to filter among extracted ones
        for database in databasesinstances:
            for tag in database["TagList"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    database_list.append(database)
        # Verify clusters with tags to filter among extracted ones
        for database in databasesclusters:
            for tag in database["TagList"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    database_list.append(database)

        print(f"end list_rds {datetime.now()}")
        if callback:
            callback(database_list, *callback_params)

   
    def list_vpn(self, client, filters, callback, callback_params):
        print(f"start list_vpn {datetime.now()}")
        vpn_list = []

        vpn_connections = client.describe_vpn_connections()["VpnConnections"]
        for vpn in vpn_connections:
            for tag in vpn["Tags"]:
                if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                    vpn_list.append(vpn)
                    break

        print(f"end list_vpn {datetime.now()}")
        if callback:
            callback(vpn_list, *callback_params)
