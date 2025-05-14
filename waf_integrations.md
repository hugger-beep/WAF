### 1. CloudFront with WAF for ROSA Workloads

``` mermaid

flowchart LR
    Users((Internet Users)) --> CloudFront[Amazon CloudFront]
    WAF[AWS WAF] --> |Protects| CloudFront
    CloudFront --> |Origin| ALB[AWS Application Load Balancer]
    ALB --> |Routes Traffic| ROSA[Red Hat OpenShift Service on AWS]
    
    subgraph AWS Cloud
        CloudFront
        WAF
        ALB
        subgraph ROSA Cluster
            ROSA
            subgraph Workloads
                API[API Services]
                Web[Web Applications]
                Microservices[Microservices]
            end
        end
    end
    
    classDef aws fill:#FF9900,stroke:#232F3E,color:white
    classDef rosa fill:#EE0000,stroke:#232F3E,color:white
    classDef network fill:#3F8624,stroke:#232F3E,color:white
    
    class CloudFront,WAF,ALB aws
    class ROSA,API,Web,Microservices rosa
    class Users network
```

### 2. ALB with WAF for ROSA Workloads

``` mermaid

flowchart LR
    Users((Internet Users)) --> ALB[AWS Application Load Balancer]
    WAF[AWS WAF] --> |Protects| ALB
    ALB --> |Routes Traffic| ROSA[Red Hat OpenShift Service on AWS]
    
    subgraph AWS Cloud
        WAF
        ALB
        subgraph ROSA Cluster
            ROSA
            subgraph Workloads
                API[API Services]
                Web[Web Applications]
                Microservices[Microservices]
            end
        end
    end
    
    classDef aws fill:#FF9900,stroke:#232F3E,color:white
    classDef rosa fill:#EE0000,stroke:#232F3E,color:white
    classDef network fill:#3F8624,stroke:#232F3E,color:white
    
    class ALB,WAF aws
    class ROSA,API,Web,Microservices rosa
    class Users network
```

### 3. AWS WAF Integrations with AWS Resources

``` mermaid


flowchart TD
    WAF[AWS WAF] --> CloudFront[Amazon CloudFront]
    WAF --> ALB[Application Load Balancer]
    WAF --> APIGW[Amazon API Gateway]
    WAF --> AppRunner[AWS App Runner]
    WAF --> Cognito[Amazon Cognito User Pool]
    WAF --> AppSync[AWS AppSync]
    
    subgraph External Access
        CloudFront --> |Origin| S3[Amazon S3]
        CloudFront --> |Origin| EC2[Amazon EC2]
        CloudFront --> |Origin| ECS[Amazon ECS]
        CloudFront --> |Origin| EKS[Amazon EKS]
        CloudFront --> |Origin| ROSA[Red Hat OpenShift]
        
        ALB --> EC2
        ALB --> ECS
        ALB --> EKS
        ALB --> ROSA
        
        APIGW --> Lambda[AWS Lambda]
        APIGW --> EC2
        APIGW --> ECS
        
        AppRunner
        Cognito
        AppSync
    end
    
    subgraph Internal Access
        PrivateLB[Internal ALB] --> PrivateEC2[Private EC2]
        PrivateLB --> PrivateECS[Private ECS]
        WAF --> PrivateLB
        
        PrivateAPIGW[Private API Gateway] --> PrivateLambda[Private Lambda]
        WAF --> PrivateAPIGW
    end
    
    classDef aws fill:#FF9900,stroke:#232F3E,color:white
    classDef security fill:#D13212,stroke:#232F3E,color:white
    classDef compute fill:#1EC9E1,stroke:#232F3E,color:white
    classDef storage fill:#3F8624,stroke:#232F3E,color:white
    
    class WAF security
    class CloudFront,ALB,APIGW,AppRunner,Cognito,AppSync,PrivateLB,PrivateAPIGW aws
    class EC2,ECS,EKS,ROSA,Lambda,PrivateEC2,PrivateECS,PrivateLambda compute
    class S3 storage
```
