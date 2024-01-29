from datetime import datetime, timedelta, timezone
import logging
import botocore.exceptions as botoexception

logger = logging.getLogger(name="resourcelister")


class ResourceLister:
    def __init__(self, filter_tag_key, filter_tag_value):
        self.filter_tag_key = filter_tag_key
        self.filter_tag_value = filter_tag_value

    @staticmethod
    def callaback_params_sanitize(callaback_params):
        # If Array -> Return callback_params
        if type(callaback_params) == list:
            return callaback_params
        # Else if Set -> Return list(callback_params)
        elif type(callaback_params) == tuple:
            return list(callaback_params)
        # Else -> Return [callback_params]
        else:
            return [callaback_params]

    @staticmethod
    def evaluate_filters(item, filters):
        """
        Method to filter item based on 
        :param item: list of items to be checked
        :param filters: filters to be checked against items
        :return: filtered list of items
        """
        if filters is None:
            return True

        for key in filters:
            if key not in item:
                return False

            if item[key] != filters[key]:
                return False
        return True

    def list_acm(self, client, filters, callback, callback_params):
        """
        Method to list certificates filtered by tags
        :param client: ACM boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_certificate
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered certificates
        """

        print(f"start list acm {datetime.now()}")
        certificates_list = []
        certificates_filtered_list = []

        paginator = client.get_paginator("list_certificates")
        pages = paginator.paginate()
        for page in pages:
            certificates_list.extend(page["CertificateSummaryList"])

        for certificate in certificates_list:
            certificate_info = client.describe_certificate(
                CertificateArn=certificate["CertificateArn"])["Certificate"]

            if ResourceLister.evaluate_filters(certificate_info, filters):
                certificate_tags = client.list_tags_for_certificate(
                    CertificateArn=certificate["CertificateArn"])["Tags"]
                for tag in certificate_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        certificate["Tags"] = certificate_tags
                        certificates_filtered_list.append(certificate)
                        break

        print(f"end list acm {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(certificates_filtered_list, *callaback_params_sanitized)

    def list_ebs(self, client, filters, callback, callback_params):
        """
        Method to list ebs filtered by tags
        :param client: EBS boto3 client
        :param filters: Maps list of filters. Pay attention that this filters are used as param of the boto3's method: describe_volumes
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered ebs
        """

        print(f"start list_ebs {datetime.now()}")
        volumes_list = []
        volumes_filtered_list = []

        paginator = client.get_paginator("describe_volumes")
        pages = paginator.paginate(Filters=filters)
        for page in pages:
            volumes_list.extend(page["Volumes"])

        for volume in volumes_list:
            # Filters only disks that have been created for at least 30 minutes
            date_to_compare = (volume["CreateTime"].replace(
                tzinfo=timezone.utc) + timedelta(minutes=30))
            my_date = datetime.now(timezone.utc)
            if date_to_compare < my_date:
                for attachment in volume["Attachments"]:
                    if attachment["State"] == "attached":
                        ec2_tags = client.describe_instances(
                            InstanceIds=[attachment["InstanceId"]])["Reservations"][0]["Instances"][0]["Tags"]
                        ec2_name = ""
                        for tag in ec2_tags:
                            if tag["Key"] == "Name":
                                ec2_name = tag["Value"]
                                break
                        break
                volume["EC2Name"] = ec2_name
                volumes_filtered_list.append(volume)

        print(f"end list_ebs {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(volumes_filtered_list, *callaback_params_sanitized)

    def list_ec2(self, client, filters, callback, callback_params):
        """
        Method to list instances filtered by tags
        :param client: EC2 boto3 client
        :param filters: Maps list of filters. Pay attention that this filters are used as param of the boto3's method: describe_instances
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered ec2
        """
        print(f"start list_ec2 {datetime.now()}")
        instances_list = []
        instances_filtered_list = []

        paginator = client.get_paginator("describe_instances")
        pages = paginator.paginate(Filters=filters)
        for page in pages:
            instances_list.extend(page["Reservations"])

        for reservation in instances_list:
            instances_filtered_list.extend(reservation["Instances"])

        print(f"end list_ec2 {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(instances_filtered_list, *callaback_params_sanitized)

    def list_efs(self, client, filters, callback, callback_params):
        """
        Method to list efs filtered by tags
        :param client: EFS boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_file_systems
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered efs
        """
        print(f"start list_efs {datetime.now()}")

        filesystem_list = []
        filesystem_filtered_list = []

        paginator = client.get_paginator("describe_file_systems")
        pages = paginator.paginate()
        for page in pages:
            filesystem_list.extend(page["FileSystems"])

        # Filter instance by tags
        for filesystem in filesystem_list:
            if ResourceLister.evaluate_filters(filesystem, filters):
                for tag in filesystem["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        filesystem_filtered_list.append(filesystem)

        print(f"end list_efs {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(filesystem_filtered_list, *callaback_params_sanitized)

    def list_eks(self, client, filters, callback, callback_params):
        """
        Method to list clusters filtered by tags
        :param client: EKS boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered eks
        """
        print(f"start list_eks {datetime.now()}")

        cluster_list = []
        cluster_filtered_list = []

        paginator = client.get_paginator("list_clusters")
        pages = paginator.paginate()
        for page in pages:
            cluster_list.extend(page["clusters"])

        for cluster in cluster_list:
            cluster_info = client.describe_cluster(name=cluster)["cluster"]
            if cluster_info is not None and ResourceLister.evaluate_filters(cluster_info, filters):
                tags = cluster_info["tags"]
                if tags.get(self.filter_tag_key, "no") == self.filter_tag_value:
                    # Tag Key/Value normalization
                    # {'Tag1': 'Value1', 'Tag2': 'Value2'}
                    # [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]

                    cluster_info["Tags"] = [
                        {"Key": k, "Value": v} for k, v in tags.items()]
                    cluster_filtered_list.append(cluster_info)

        print(f"end list_eks {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(cluster_filtered_list, *callaback_params_sanitized)

    def list_elb(self, client, filters, callback, callback_params):
        """
        Method to list application and network load balancer filtered by tags. There is already the code for gateway but they are not returned
        :param client: ELB boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_load_balancers
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered elb
        """
        print(f"start list_elb {datetime.now()}")

        loadbalancer_list = []
        alb_filtered_list = []
        nlb_filtered_list = []

        paginator = client.get_paginator("describe_load_balancers")
        pages = paginator.paginate()
        for page in pages:
            loadbalancer_list.extend(page["LoadBalancers"])

        # Split loadbalancer_list in block of 20 items and extract tags
        splitedSize = 20
        tags = []
        lb_splited = [loadbalancer_list[x:x+splitedSize]
                      for x in range(0, len(loadbalancer_list), splitedSize)]
        for lb in lb_splited:
            tags.extend(client.describe_tags(
                ResourceArns=[loadbalancer["LoadBalancerArn"] for loadbalancer in lb])["TagDescriptions"])

        for loadbalancer in loadbalancer_list:
            # Keep track of the location of the tagset so that you can delete it from the tags
            index_lb_tag = -1
            for index, taglist in enumerate(tags):
                if taglist["ResourceArn"] == loadbalancer["LoadBalancerArn"]:
                    index_lb_tag = index
                    break

            if index_lb_tag > -1:
                for tag in tags[index_lb_tag]["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value and ResourceLister.evaluate_filters(loadbalancer, filters):
                        # We add to the loadbalancer all its tags. It is needed since in the init of CloudWatchALB we use
                        # also tags to establish the name of the ci
                        loadbalancer["Tags"] = taglist["Tags"]

                        if loadbalancer["Type"] == "application":
                            alb_filtered_list.append(loadbalancer)
                        elif loadbalancer["Type"] == "network":
                            nlb_filtered_list.append(loadbalancer)
                        elif loadbalancer["Type"] == "gateway":
                            pass

                        break
                tags.pop(index_lb_tag)
        print(f"end list_elb {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(alb_filtered_list, nlb_filtered_list,
                     *callaback_params_sanitized)

    def list_elbtg(self, client, filters, callback, callback_params):
        """
        Method to list load balancers target groups filtered by tags
        :param client: ELB boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_target_groups
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered elbtg
        """
        print(f"start list_elbtg {datetime.now()}")
        # I retrieve the tags of the target group so I can extract its name
        # elbarn: [tg_with_that_arn, ...]

        targetgroup_list = []  # Initial list of all target groups
        targetgroups_elbs_arn = {}  # Map of all load balancers with associated target groups

        # Target Group listing
        paginator = client.get_paginator("describe_target_groups")
        pages = paginator.paginate()
        for page in pages:
            targetgroup_list.extend(page["TargetGroups"])

        # Create list of load balancers from target group list
        for tg in targetgroup_list:
            # Checks whether the target group has an associated balancer
            if len(tg["LoadBalancerArns"]) > 0:
                elb_arn = tg["LoadBalancerArns"][0]
                if elb_arn not in targetgroups_elbs_arn:
                    targetgroups_elbs_arn[elb_arn] = []
                #  Append the target group to the list of target groups associated with the elb loadbalancer
                targetgroups_elbs_arn[elb_arn].append(tg)

        # Verify the target groups based on the type of the associated elb
        loadbalancer_list = []
        # List all load balancers
        paginator = client.get_paginator("describe_load_balancers")
        pages = paginator.paginate()
        for page in pages:
            loadbalancer_list.extend(page["LoadBalancers"])

        # Check if each tg is associated with a load balancer of type network or application and save the type in the tg object inside targetgroups_elbs_arn
        for elb in loadbalancer_list:
            if elb["Type"] in ["application", "network"] and len(targetgroups_elbs_arn.get(elb["LoadBalancerArn"], [])) > 0:
                # I assign to each tg the type of balancer with which they are associated
                for tg in targetgroups_elbs_arn[elb["LoadBalancerArn"]]:
                    tg["ELBType"] = elb["Type"]
            elif elb["Type"] in ["gateway"]:
                # Remove from elbarn map: [pos_tg_with_that_arn, ...] arn of balancers not in the list
                del targetgroups_elbs_arn[elb["LoadBalancerArn"]]

        # Create new unique array with all tgs info + lbtype
        targetgroups_with_lbtype = []
        for key in targetgroups_elbs_arn:
            targetgroups_with_lbtype.extend(targetgroups_elbs_arn[key])

        # Create new list with only the arn of the tgs for tag extraction
        targetgroups_arn = []
        for tg in targetgroups_with_lbtype:
            targetgroups_arn.append(tg["TargetGroupArn"])

        targetgroups_arn_tags = []  # Temporary list of TG tags
        # Split target groups in block of 20 items and extract tags
        splitedSize = 20
        tg_arn_splitted = [targetgroups_arn[x:x+splitedSize]
                           for x in range(0, len(targetgroups_arn), splitedSize)]
        for tg in tg_arn_splitted:
            targetgroups_arn_tags = client.describe_tags(
                ResourceArns=tg)["TagDescriptions"]
            # Check if the tg has the filter tag key and value and then put tags in original list
            for tg_arn_tags in targetgroups_arn_tags:
                has_tag = False
                for tag in tg_arn_tags["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        has_tag = True
                        # Find same target group in original list and insert the tags in it (if not already present)
                        for targetgroup_with_lbtype in targetgroups_with_lbtype:
                            if targetgroup_with_lbtype["TargetGroupArn"] == tg_arn_tags["ResourceArn"]:
                                targetgroup_with_lbtype["Tags"] = tg_arn_tags["Tags"]
                                break
                        break

                if not has_tag:
                    # Find same target group in original list and remove it from the list
                    targetgroup_toremove_index = -1
                    for index in range(0, len(targetgroups_with_lbtype)):
                        if targetgroups_with_lbtype[index]["TargetGroupArn"] == tg_arn_tags["ResourceArn"]:
                            targetgroup_toremove_index = index
                            break
                    # Remove the element
                    if targetgroup_toremove_index != -1:
                        del targetgroups_with_lbtype[targetgroup_toremove_index]

        alb_tg_list = []  # Target group of Application Load Balancer
        nlb_tg_list = []  # Target group of Network Load Balancer
        # Evaluate filter and then insert tg in appropriate list (Application or Network Load Balancer)
        for tg in targetgroups_with_lbtype:
            if ResourceLister.evaluate_filters(tg, filters):
                if tg["ELBType"] == "application":
                    alb_tg_list.append(tg)
                elif tg["ELBType"] == "network":
                    nlb_tg_list.append(tg)

        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(alb_tg_list, nlb_tg_list, *callaback_params_sanitized)
        print(f"end list_elbtg {datetime.now()}")

    def list_os(self, client, filters, callback, callback_params):
        """
        Method to list OpenSearch Domains filtered by tags
        :param client: OpenSearch boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_domain
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered OpenSearch Domains
        """
        print(f"start list_os {datetime.now()}")
        domains_list = []

        os_names = client.list_domain_names()["DomainNames"]

        for os in os_names:
            os_details = client.describe_domain(
                DomainName=os["DomainName"])["DomainStatus"]
            if os_details is not None:
                os_tags = client.list_tags(ARN=os_details["ARN"])["TagList"]
                if ResourceLister.evaluate_filters(os_details, filters):
                    for tag in os_tags:
                        if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                            os_details["Tags"] = os_tags
                            domains_list.append(os_details)
                            break
        print(f"end list_os {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(domains_list, *callaback_params_sanitized)

    def list_rds(self, client, instance_filters, cluster_filters, callback, callback_params):
        """
        Method to list db instances filtered by tags
        :param client: RDS boto3 client
        :param instance_filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_db_instances
        :param cluster_filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_db_clusters
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered rds instances
        """
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
            if ResourceLister.evaluate_filters(database, instance_filters):
                for tag in database["TagList"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        database_list.append(database)
        # Verify clusters with tags to filter among extracted ones
        for database in databasesclusters:
            if ResourceLister.evaluate_filters(database, cluster_filters):
                for tag in database["TagList"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        database_list.append(database)

        print(f"end list_rds {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(database_list, *callaback_params_sanitized)

    def list_s3(self, client, filters, callback, callback_params):
        """
        Method to list S3 filtered by tags
        :param client: S3 boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_vpn_connections
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered bucket
        """
        print(f"start list_s3 {datetime.now()}")

        bucket_list = []
        region = client.meta.region_name
        buckets = client.list_buckets()["Buckets"]
        for bucket in buckets:
            try:
                bucket_location = client.get_bucket_location(Bucket=bucket["Name"])[
                    "LocationConstraint"]
                bucket_tags = {}
                if bucket_location == region:
                    try:
                        bucket_tags = client.get_bucket_tagging(
                            Bucket=bucket["Name"])
                    except botoexception.ClientError as error:
                        if not error.response['Error']['Code'] == "NoSuchTagSet":
                            logger.error(error)
                    bucket_tags = bucket_tags.get("TagSet", None)
                    if ResourceLister.evaluate_filters(bucket, filters) and bucket_tags is not None:
                        for tag in bucket_tags:
                            if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                                bucket["Tags"] = bucket_tags
                                bucket_list.append(bucket)
                                break
            except botoexception.ClientError as error:
                logger.error(error)

        print(f"end list_s3 {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(bucket_list, *callaback_params_sanitized)

    def list_vpn(self, client, filters, callback, callback_params):
        """
        Method to list vpn filtered by tags
        :param client: VPN boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_vpn_connections
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered vpn
        """
        print(f"start list_vpn {datetime.now()}")
        vpn_list = []

        vpn_connections = client.describe_vpn_connections()["VpnConnections"]
        for vpn in vpn_connections:
            if ResourceLister.evaluate_filters(vpn, filters):
                for tag in vpn["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        vpn_list.append(vpn)
                        break

        print(f"end list_vpn {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(vpn_list, *callaback_params_sanitized)

    def list_lambda(self, client, filters, callback, callback_params):
        """
        Method to list lambda functions filtered by tags
        :param client: Lambda boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered lambda
        """
        print(f"start list_lambda {datetime.now()}")
        function_list = []
        function_filtered_list = []

        paginator = client.get_paginator("list_functions")
        pages = paginator.paginate()
        for page in pages:
            function_list.extend(page["Functions"])

        for function in function_list:
            if ResourceLister.evaluate_filters(function, filters):
                tags = client.list_tags(
                    Resource=function["FunctionArn"])["Tags"]
                if tags.get(self.filter_tag_key, "no") == self.filter_tag_value:
                    # Tag Key/Value normalization
                    # {'Tag1': 'Value1', 'Tag2': 'Value2'}
                    # [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]

                    function["Tags"] = [
                        {"Key": k, "Value": v} for k, v in tags.items()]
                    function_filtered_list.append(function)

        print(f"end list_lambda {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(function_filtered_list, *callaback_params_sanitized)

    def list_autoscaling(self, client, filters, callback, callback_params):
        """
        Method to list autoscaling functions filtered by tags
        :param client: autoscaling boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered autoscaling
        """

        print(f"start list_autoscaling {datetime.now()}")
        autoscaling_list = []
        autoscaling_filtered_list = []

        paginator = client.get_paginator("describe_auto_scaling_groups")
        pages = paginator.paginate()
        for page in pages:
            autoscaling_list.extend(page["AutoScalingGroups"])

        for autoscaling_group in autoscaling_list:
            if ResourceLister.evaluate_filters(autoscaling_group, filters):
                for tag in autoscaling_group["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        autoscaling_filtered_list.append(autoscaling_group)
                        break

        print(f"end list_autoscaling {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(autoscaling_filtered_list, *callaback_params_sanitized)

    def list_storagegateway(self, client, filters, callback, callback_params):
        """
        Method to list storage gateways filtered by tags
        :param client: storage gateway boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered storage gateway
        """

        print(f"start list_storagegateway {datetime.now()}")
        gateway_list = []
        gateway_filtered_list = []

        paginator = client.get_paginator("list_gateways")
        pages = paginator.paginate()
        for page in pages:
            gateway_list.extend(page["Gateways"])

        for gateway in gateway_list:
            if ResourceLister.evaluate_filters(gateway, filters):
                gateway_info = client.describe_gateway_information(
                    GatewayARN=gateway["GatewayARN"])
                for tag in gateway_info["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        gateway["Tags"] = gateway_info["Tags"]
                        gateway_filtered_list.append(gateway)
                        break

        print(f"end list_storagegateway {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(gateway_filtered_list, *callaback_params_sanitized)

    def list_apigateway(self, client, filters, callback, callback_params):
        """
        Method to list api gateways filtered by tags
        :param client: api gateway boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered api gateway
        """

        print(f"start list_apigateway {datetime.now()}")
        api_list = []
        api_filtered_list = []

        # apigatewayv2
        if client._service_model.service_name == "apigatewayv2":
            paginator = client.get_paginator("get_apis")
            pages = paginator.paginate()
            for page in pages:
                api_list.extend(page["Items"])

            for api in api_list:
                if ResourceLister.evaluate_filters(api, filters):
                    if api["Tags"].get(self.filter_tag_key, "no") == self.filter_tag_value:
                        # Tag Key/Value normalization
                        # tags = {'Tag1': 'Value1', 'Tag2': 'Value2'}
                        # Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
                        api["tags"] = api["Tags"]
                        api["Tags"] = [
                            {"Key": k, "Value": v} for k, v in api["tags"].items()]
                        api_filtered_list.append(api)
                        break

        # apigateway
        elif client._service_model.service_name == "apigateway":
            paginator = client.get_paginator("get_rest_apis")
            pages = paginator.paginate()
            for page in pages:
                api_list.extend(page["items"])

            for api in api_list:
                if ResourceLister.evaluate_filters(api, filters) and "tags" in api:
                    if api["tags"].get(self.filter_tag_key, "no") == self.filter_tag_value:
                        # Tag Key/Value normalization
                        # tags = {'Tag1': 'Value1', 'Tag2': 'Value2'}
                        # Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
                        api["Tags"] = [
                            {"Key": k, "Value": v} for k, v in api["tags"].items()]
                        api_filtered_list.append(api)
                        break

        print(f"end list_apigateway {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(api_filtered_list, *callaback_params_sanitized)

    def list_waf(self, client, filters, callback, callback_params, scope="REGIONAL"):
        """
        Method to list waf acl filtered by tags
        :param client: waf boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :param scope: Specifies whether this is for an Amazon CloudFront distribution or for a regional application. A regional application can be an Application Load Balancer (ALB), an Amazon API Gateway REST API, an AppSync GraphQL API, or an Amazon Cognito user pool.
        :return: list of filtered waf acl
        """

        print(f"start list_waf {datetime.now()}")
        acls_list = []
        acls_filtered_list = []

        next_token = ""
        # Download first block
        # It is not possible use a single while because list_web_acls method does not accept NextToken as empty string
        response = client.list_web_acls(Scope=scope)
        acls_list.extend(response["WebACLs"])
        next_token = response.get("NextMarker", None)
        # Download other functions if available
        while next_token is not None:
            response = client.list_web_acls(Scope=scope, NextMarker=next_token)
            next_token = response.get("NextMarker", None)
            acls_list.extend(response["WebACLs"])

        for acl in acls_list:
            acl_tags = client.list_tags_for_resource(ResourceARN=acl["ARN"])[
                "TagInfoForResource"]["TagList"]
            if ResourceLister.evaluate_filters(acl, filters):
                for tag in acl_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        acl["Tags"] = acl_tags
                        acls_filtered_list.append(acl)
                        break

        print(f"end list_waf {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(acls_filtered_list, *callaback_params_sanitized)

    def list_cloudfront(self, client, filters, callback, callback_params):
        """
        Method to list cloudfront distributions filtered by tags
        :param client: cloudfront boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered cloudfront distributions
        """

        print(f"start list_cloudfront {datetime.now()}")
        distributions_list = []
        distributions_filtered_list = []

        paginator = client.get_paginator("list_distributions")
        pages = paginator.paginate()
        for page in pages:
            distributions_list.extend(
                page["DistributionList"].get("Items", []))

        for distribution in distributions_list:
            distribution_tags = client.list_tags_for_resource(
                Resource=distribution["ARN"])["Tags"]["Items"]
            if ResourceLister.evaluate_filters(distribution, filters):
                for tag in distribution_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        distribution["Tags"] = distribution_tags
                        distributions_filtered_list.append(distribution)
                        break

        print(f"end list_cloudfront {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(distributions_filtered_list, *callaback_params_sanitized)

    def list_ecr(self, client, filters, callback, callback_params):
        """
        Method to list ecr registries filtered by tags
        :param client: ecr boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered ecr registries
        """

        print(f"start list_ecr {datetime.now()}")
        registries_list = []
        registries_filtered_list = []

        paginator = client.get_paginator("describe_repositories")
        pages = paginator.paginate()
        for page in pages:
            registries_list.extend(page["repositories"])

        for registry in registries_list:
            registries_tags = client.list_tags_for_resource(
                resourceArn=registry["repositoryArn"])["tags"]
            if ResourceLister.evaluate_filters(registry, filters):
                for tag in registries_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        registry["Tags"] = registries_tags
                        registries_filtered_list.append(registry)
                        break

        print(f"end list_ecr {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(registries_filtered_list, *callaback_params_sanitized)

    def list_appstream(self, client, filters, callback, callback_params):
        """
        Method to list Appstream fleets filtered by tags
        :param client: Appstream boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_cluster
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered appstream fleets
        """

        print(f"start list_appstream {datetime.now()}")
        fleets_list = []
        fleets_filtered_list = []

        paginator = client.get_paginator("describe_fleets")
        pages = paginator.paginate()
        for page in pages:
            fleets_list.extend(page["Fleets"])

        for fleet in fleets_list:
            fleets_tags = client.list_tags_for_resource(
                ResourceArn=fleet["Arn"])["Tags"]
            if ResourceLister.evaluate_filters(fleet, filters):
                if fleets_tags.get(self.filter_tag_key, "no") == self.filter_tag_value:
                    # Tag Key/Value normalization
                    # tags = {'Tag1': 'Value1', 'Tag2': 'Value2'}
                    # Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
                    fleet["Tags"] = [
                        {"Key": k, "Value": v} for k, v in fleets_tags.items()]
                    fleets_filtered_list.append(fleet)
                    break

        print(f"end list_appstream {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(fleets_filtered_list, *callaback_params_sanitized)

    def list_ecs(self, client, filters, callback, callback_params):
        """
        Method to list ECS Clusters filtered by tags
        :param client: ECS boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_domain
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered OpeECSnSearch Clusters
        """
        print(f"start list_ecs {datetime.now()}")
        clusters_list = []
        clusters_arn_list = []
        clusters_filtered_list = []

        paginator = client.get_paginator("list_clusters")
        pages = paginator.paginate()
        for page in pages:
            clusters_arn_list.extend(page["clusterArns"])

        clusters_list = client.describe_clusters(
            clusters=clusters_arn_list)["clusters"]

        for cluster in clusters_list:
            # Tags from "describe_clusters" seems to be broken, retrieved with the specific call
            cluster_tags = client.list_tags_for_resource(
                resourceArn=cluster["clusterArn"])["tags"]
            if ResourceLister.evaluate_filters(cluster, filters):
                # Tags = [{'key': 'Tag1', 'value': 'Value1'},{'key': 'Tag2', 'value': 'Value2'}]
                # Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
                cluster["Tags"] = []
                for tag in cluster_tags:
                    cluster["Tags"].append(
                        {"Key": tag["key"], "Value": tag["value"]})
                for tag in cluster["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        clusters_filtered_list.append(cluster)
                        break
        print(f"end list_ecs {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(clusters_filtered_list, *callaback_params_sanitized)

    def list_route53(self, client, filters, callback, callback_params):
        """
        Method to list Route53 Domains filtered by tags
        :param client: Route53 boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_domain
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered Route53 Domains
        """
        print(f"start list_route53 {datetime.now()}")
        domains_list = []
        domains_filtered_list = []

        paginator = client.get_paginator("list_hosted_zones")
        pages = paginator.paginate()
        for page in pages:
            domains_list.extend(page["HostedZones"])

        for domain in domains_list:
            domain_tags = client.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=domain["Id"].split("/")[2])["ResourceTagSet"]["Tags"]
            if ResourceLister.evaluate_filters(domain, filters):
                domain["Tags"] = domain_tags
                for tag in domain["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        domains_filtered_list.append(domain)
                        break
        print(f"end list_route53 {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(domains_filtered_list, *callaback_params_sanitized)

    def list_sns(self, client, filters, callback, callback_params):
        """
        Method to list SNS Topic filtered by tags
        :param client: SNS boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_topic
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered SNS Topic
        """
        print(f"start list_sns {datetime.now()}")
        topics_list = []
        topics_filtered_list = []

        paginator = client.get_paginator("list_topics")
        pages = paginator.paginate()
        for page in pages:
            topics_list.extend(page["Topics"])

        for topic in topics_list:
            topic_tags = client.list_tags_for_resource(
                ResourceArn=topic["TopicArn"])["Tags"]
            if ResourceLister.evaluate_filters(topic, filters):
                topic["Tags"] = topic_tags
                for tag in topic["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        topics_filtered_list.append(topic)
                        break
        print(f"end list_sns {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(topics_filtered_list, *callaback_params_sanitized)

    def list_ses(self, client, filters, callback, callback_params):
        """
        Method to list ses identity filtered by tags
        :param client: ses boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_identity
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered ses identity
        """
        print(f"start list_ses {datetime.now()}")
        identities_list = []
        identities_filtered_list = []
        identities_info_list = []

        next_token = ""
        # Download first block
        # It is not possible use a single while because list_email_identities method does not accept NextToken as empty string
        response = client.list_email_identities()
        identities_list.extend(response["EmailIdentities"])
        next_token = response.get("NextToken", None)
        # Download other functions if available
        while next_token is not None:
            response = client.list_email_identities(NextToken=next_token)
            next_token = response.get("NextToken", None)
            identities_list.extend(response["EmailIdentities"])

        for identity in identities_list:
            identities_info_list = client.get_email_identity(
                EmailIdentity=identity["IdentityName"])
            identities_info_list["IdentityName"] = identity["IdentityName"]
            if ResourceLister.evaluate_filters(identity, filters):
                for tag in identities_info_list["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        identities_filtered_list.append(identities_info_list)
                        break
        print(f"end list_ses {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(identities_filtered_list, *callaback_params_sanitized)

    def list_sns(self, client, filters, callback, callback_params):
        """
        Method to list SNS Topic filtered by tags
        :param client: SNS boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_topic
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered SNS Topic
        """
        print(f"start list_sns {datetime.now()}")
        topics_list = []
        topics_filtered_list = []

        paginator = client.get_paginator("list_topics")
        pages = paginator.paginate()
        for page in pages:
            topics_list.extend(page["Topics"])

        for topic in topics_list:
            topic_tags = client.list_tags_for_resource(
                ResourceArn=topic["TopicArn"])["Tags"]
            if ResourceLister.evaluate_filters(topic, filters):
                topic["Tags"] = topic_tags
                for tag in topic["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        topics_filtered_list.append(topic)
                        break
        print(f"end list_sns {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(topics_filtered_list, *callaback_params_sanitized)

    def list_sqs(self, client, filters, callback, callback_params):
        """
        Method to list sqs queue filtered by tags
        :param client: sqs boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_queue
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered sqs queue
        """
        print(f"start list_sqs {datetime.now()}")
        queues_url_list = []
        queues_filtered_list = []
        queues_tags = []
        queue = {}
        paginator = client.get_paginator("list_queues")
        pages = paginator.paginate()
        for page in pages:
            queues_url_list.extend(page.get("QueueUrls", []))

        for queue_url in queues_url_list:
            queue["QueueUrl"] = queue_url
            queues_tags = client.list_queue_tags(
                QueueUrl=queue_url).get("Tags", {})
            if ResourceLister.evaluate_filters(queue_url, filters):
                if queues_tags.get(self.filter_tag_key, "no") == self.filter_tag_value:
                    # Tag Key/Value normalization
                    # tags = {'Tag1': 'Value1', 'Tag2': 'Value2'}
                    # Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
                    queue["Tags"] = [
                        {"Key": k, "Value": v} for k, v in queues_tags.items()]
                    queues_filtered_list.append(queue)
        print(f"end list_sqs {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(queues_filtered_list, *callaback_params_sanitized)

    def list_directory(self, client, filters, callback, callback_params):
        """
        Method to list directory filtered by tags
        :param client: directory boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_directory
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered directory
        """
        print(f"start list_directory {datetime.now()}")
        directories_list = []
        directories_filtered_list = []
        directories_tags = []
        directory = {}
        paginator = client.get_paginator("describe_directories")
        pages = paginator.paginate()
        for page in pages:
            directories_list.extend(page["DirectoryDescriptions"])

        for directory in directories_list:
            paginator = client.get_paginator("list_tags_for_resource")
            pages = paginator.paginate(ResourceId=directory["DirectoryId"])
            for page in pages:
                directories_tags.extend(page["Tags"])

            if ResourceLister.evaluate_filters(directory, filters):
                directory["Tags"] = directories_tags
                for tag in directory["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        directories_filtered_list.append(directory)
                        break
        print(f"end list_directory {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(directories_filtered_list, *callaback_params_sanitized)

    def list_subnets(self, client, filters, callback, callback_params):
        """
        Method to list subnets filtered by tags
        :param client: directory boto3 client
        :param filters: Maps list of filters. Those filters are manually checked. the key is the name of the attribute to check from the object, and the value is the value you expect as value. The attributes you can use are the once in the response of the boto3's method: describe_directory
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered subnets
        """
        print(f"start list_subnets {datetime.now()}")
        subnets_list = []
        subnets_filtered_list = []

        paginator = client.get_paginator("describe_subnets")
        pages = paginator.paginate()
        for page in pages:
            subnets_list.extend(page["Subnets"])

        for subnet in subnets_list:
            if ResourceLister.evaluate_filters(subnet, filters):
                for tag in subnet.get("Tags", []):
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        subnets_filtered_list.append(subnet)
                        break
        print(f"end list_subnets {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(subnets_filtered_list, *callaback_params_sanitized)
    # Code Build non supporta il tagging

    def list_codepipeline(self, client,filters, callback, callback_params):
        """
        Method to list codepipeline
        :param client: directory boto3 client
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of filtered codepipeline
        """
        print(f"start list_codepipeline {datetime.now()}")
        codepipeline_lists = []
        codepipeline_filtered_list = []

        paginator = client.get_paginator("list_pipelines")
        pages = paginator.paginate()
        for page in pages:
                response = client.get_pipeline(name=f"{page['name']}")
                tags = client.list_tags_for_resource(resourceArn= response['metadata']['pipelineArn'] )
                codepipeline = {'Pipeline':response['pipeline'], 'Tags':tags['tags']}
                codepipeline_lists.append(codepipeline)
        for pipeline in codepipeline_lists:
            if ResourceLister.evaluate_filters(pipeline, filters):
                for tag in pipeline.get("Tags", []):
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        codepipeline_filtered_list.append(pipeline)
                        break
        print(f"end list_codepipeline {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(codepipeline_filtered_list, *callaback_params_sanitized)
            
    def list_codebuild(self, client, callback, callback_params):
        """
        Method to list codebuild
        :param client: directory boto3 client
        :param callback: Method to be called after the listing
        :param callback_params: Params to be passed to callback method
        :return: list of codebuild
        """
        print(f"start list_codebuild {datetime.now()}")
        codebuilds_list = []
        paginator = client.get_paginator("list_projects")
        pages = paginator.paginate()
        for page in pages:
            codebuilds_list.extend(page["projects"])
        print(f"end list_codebuild {datetime.now()}")
        if callback:
            callaback_params_sanitized = ResourceLister.callaback_params_sanitize(
                callback_params)
            callback(codebuilds_list, *callaback_params_sanitized)

        

