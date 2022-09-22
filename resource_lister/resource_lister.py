from datetime import datetime, timedelta, timezone
from logging import Logger
import botocore.exceptions as botoexception

class ResourceLister:
    def __init__(self, filter_tag_key, filter_tag_value):
        self.filter_tag_key = filter_tag_key
        self.filter_tag_value = filter_tag_value

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
            callback(certificates_filtered_list, *callback_params)

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
            callback(volumes_filtered_list, *callback_params)

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
            callback(instances_filtered_list, *callback_params)

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
            callback(filesystem_filtered_list, *callback_params)

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
            callback(cluster_filtered_list, *callback_params)

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
        

        # Filter elb by tags
        if len(loadbalancer_list) > 0:
            tags = client.describe_tags(
                ResourceArns=[loadbalancer["LoadBalancerArn"] for loadbalancer in loadbalancer_list])["TagDescriptions"]
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
            callback(alb_filtered_list, nlb_filtered_list, *callback_params)

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
        
        targetgroup_list = []
        targetgroups_elbs_arn = {}
        
        paginator = client.get_paginator("describe_target_groups")
        pages = paginator.paginate()
        for page in pages:
            targetgroup_list.extend(page["TargetGroups"])


        for tg in targetgroup_list:
            # Checks whether the target group has an associated balancer
            if len(tg["LoadBalancerArns"]) > 0:
                elb_arn = tg["LoadBalancerArns"][0]
                if elb_arn not in targetgroups_elbs_arn:
                    targetgroups_elbs_arn[elb_arn] = []

                targetgroups_elbs_arn[elb_arn].append(tg)

        # Verify the target groups based on the type of the associated elb
        # client.describe_load_balancers(LoadBalancerArns=list(targetgroups_elbs_arn.keys()))
        loadbalancer_list = []
        loadbalancer_filtered_list = []
        
        paginator = client.get_paginator("describe_load_balancers")
        pages = paginator.paginate()
        for page in pages:
            loadbalancer_list.extend(page["LoadBalancers"])

    
        for elb in loadbalancer_list:
            if elb["Type"] in ["application", "network"]:
                # I assign to each tg the type of balancer with which they are associated
                for tg in targetgroups_elbs_arn[elb["LoadBalancerArn"]]:
                    tg["ELBType"] = elb["Type"]
            elif elb["Type"] in ["gateway"]:
                # Remove from elbarn map: [pos_tg_with_that_arn, ...] arn of balancers not in the list
                del targetgroups_elbs_arn[elb["LoadBalancerArn"]]

            loadbalancer_filtered_list.extend(loadbalancer_list)

        # Create unique array with all tgs
        targetgroups = []
        for key in targetgroups_elbs_arn:
            targetgroups.extend(targetgroups_elbs_arn[key])

        # Download tags of all tgs
        targetgroups_arn = []
        for tg in targetgroups:
            targetgroups_arn.append(tg["TargetGroupArn"])

        # Check if tgs have the tag to monitor them
        targetgroup_filtered_list = []
        if len(targetgroups_arn) > 0:
            targetgroup_filtered_list = client.describe_tags(
                ResourceArns=targetgroups_arn)["TagDescriptions"]

        alb_tg_list = []
        nlb_tg_list = []
        for tg in targetgroups:
            if ResourceLister.evaluate_filters(tg, filters):
                index_tg_tag = -1
                for index, taglist in enumerate(targetgroup_filtered_list):
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
                    tg["Tags"] = targetgroup_filtered_list[index_tg_tag]["Tags"]

                    if tg["ELBType"] == "application":
                        alb_tg_list.append(tg)
                    elif tg["ELBType"] == "network":
                        nlb_tg_list.append(tg)
                    targetgroup_filtered_list.pop(index_tg_tag)
        if callback:
            callback(alb_tg_list, nlb_tg_list,
                     targetgroup_filtered_list, *callback_params)
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
            callback(domains_list, *callback_params)

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
            callback(database_list, *callback_params)

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
                bucket_tags={}
                if bucket_location == region:
                    try:
                        bucket_tags = client.get_bucket_tagging(
                        Bucket=bucket["Name"])
                    except botoexception.ClientError as error:
                        if not error.response['Error']['Code'] == "NoSuchTagSet":
                            Logger.error(error)
                    bucket_tags=bucket_tags.get("TagSet", None)
                    if ResourceLister.evaluate_filters(bucket, filters) and bucket_tags is not None:
                        for tag in bucket_tags:
                            if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                                bucket["Tags"] = bucket_tags
                                bucket_list.append(bucket)
                                break
            except botoexception.ClientError as error:
                Logger.error(error)

        print(f"end list_s3 {datetime.now()}")
        if callback:
            callback(bucket_list, *callback_params)

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
            callback(vpn_list, *callback_params)

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
            callback(function_filtered_list, *callback_params)

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
            callback(autoscaling_filtered_list, *callback_params)

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
                gateway_info = client.describe_gateway_information(GatewayARN=gateway["GatewayARN"])
                for tag in gateway_info["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        gateway["Tags"] = gateway_info["Tags"]
                        gateway_filtered_list.append(gateway)
                        break

        print(f"end list_storagegateway {datetime.now()}")
        if callback:
            callback(gateway_filtered_list, *callback_params)

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
            callback(api_filtered_list, *callback_params)


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
            acl_tags = client.list_tags_for_resource(ResourceARN=acl["ARN"])["TagInfoForResource"]["TagList"]
            if ResourceLister.evaluate_filters(acl, filters):
                for tag in acl_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        acl["Tags"]=acl_tags
                        acls_filtered_list.append(acl)
                        break

        print(f"end list_waf {datetime.now()}")
        if callback:
            callback(acls_filtered_list, *callback_params)

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
            distributions_list.extend(page["DistributionList"].get("Items", []))
        
        for distribution in distributions_list:
            distribution_tags = client.list_tags_for_resource(Resource=distribution["ARN"])["Tags"]["Items"]
            if ResourceLister.evaluate_filters(distribution, filters):
                for tag in distribution_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        distribution["Tags"]=distribution_tags
                        distributions_filtered_list.append(distribution)
                        break

        print(f"end list_cloudfront {datetime.now()}")
        if callback:
            callback(distributions_filtered_list, *callback_params)

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
            registries_tags = client.list_tags_for_resource(resourceArn=registry["repositoryArn"])["tags"]
            if ResourceLister.evaluate_filters(registry, filters):
                for tag in registries_tags:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        registry["Tags"]=registries_tags
                        registries_filtered_list.append(registry)
                        break

        print(f"end list_ecr {datetime.now()}")
        if callback:
            callback(registries_filtered_list, *callback_params)

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
            fleets_tags = client.list_tags_for_resource(ResourceArn=fleet["Arn"])["Tags"]
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
            callback(fleets_filtered_list, *callback_params)


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

        clusters_list = client.describe_clusters(clusters=clusters_arn_list)["clusters"]
        
        for cluster in clusters_list:
            # Tags from "describe_clusters" seems to be broken, retrieved with the specific call
            cluster_tags = client.list_tags_for_resource(resourceArn=cluster["clusterArn"])["tags"]
            if ResourceLister.evaluate_filters(cluster, filters):
                # Tags = [{'key': 'Tag1', 'value': 'Value1'},{'key': 'Tag2', 'value': 'Value2'}]
                # Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
                cluster["Tags"] = []
                for tag in cluster_tags:
                    cluster["Tags"].append({"Key": tag["key"], "Value": tag["value"]})
                for tag in cluster["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        clusters_filtered_list.append(cluster)
                        break
        print(f"end list_ecs {datetime.now()}")
        if callback:
            callback(clusters_filtered_list, *callback_params)

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
            domain_tags = client.list_tags_for_resource(ResourceType="hostedzone", ResourceId=domain["Id"].split("/")[2])["ResourceTagSet"]["Tags"]
            if ResourceLister.evaluate_filters(domain, filters):
                domain["Tags"] = domain_tags
                for tag in domain["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        domains_filtered_list.append(domain)
                        break
        print(f"end list_route53 {datetime.now()}")
        if callback:
            callback(domains_filtered_list, *callback_params)

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
            topic_tags = client.list_tags_for_resource(ResourceArn=topic["TopicArn"])["Tags"]
            if ResourceLister.evaluate_filters(topic, filters):
                topic["Tags"] = topic_tags
                for tag in topic["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        topics_filtered_list.append(topic)
                        break
        print(f"end list_sns {datetime.now()}")
        if callback:
            callback(topics_filtered_list, *callback_params)

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
            identities_info_list = client.get_email_identity(EmailIdentity=identity["IdentityName"])
            identities_info_list["IdentityName"] = identity["IdentityName"]
            if ResourceLister.evaluate_filters(identity, filters):
                for tag in identities_info_list["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        identities_filtered_list.append(identities_info_list)
                        break
        print(f"end list_ses {datetime.now()}")
        if callback:
            callback(identities_filtered_list, *callback_params)


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
            topic_tags = client.list_tags_for_resource(ResourceArn=topic["TopicArn"])["Tags"]
            if ResourceLister.evaluate_filters(topic, filters):
                topic["Tags"] = topic_tags
                for tag in topic["Tags"]:
                    if tag["Key"] == self.filter_tag_key and tag["Value"] == self.filter_tag_value:
                        topics_filtered_list.append(topic)
                        break
        print(f"end list_sns {datetime.now()}")
        if callback:
            callback(topics_filtered_list, *callback_params)

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
            queues_url_list.extend(page["QueueUrls"])
        
        for queue_url in queues_url_list:
            queue["QueueUrl"] = queue_url
            queues_tags = client.list_queue_tags(QueueUrl=queue_url)["Tags"]
            if ResourceLister.evaluate_filters(queue_url, filters):
                if queues_tags.get(self.filter_tag_key, "no") == self.filter_tag_value:
                    # Tag Key/Value normalization
                    # tags = {'Tag1': 'Value1', 'Tag2': 'Value2'}
                    # Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
                    queue["Tags"] = [
                        {"Key": k, "Value": v} for k, v in queues_tags.items()]
                    queues_filtered_list.append(queue)
                    break
        print(f"end list_sqs {datetime.now()}")
        if callback:
            callback(queues_filtered_list, *callback_params)

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
            callback(directories_filtered_list, *callback_params)            