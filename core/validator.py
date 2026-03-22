from utils.helpers import validate_domain, print_error

class DomainValidator:
    @staticmethod
    def validate(domain):
        validated_domain = validate_domain(domain)
        
        if not validated_domain:
            print_error("Invalid domain format. Please provide a valid domain like 'example.com'")
            return None
        
        return validated_domain
    
    @staticmethod
    def sanitize_input(domain):
        if not domain:
            return None
        
        domain = domain.strip()
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('://')[1]
        
        domain = domain.split('/')[0]
        
        return domain.lower() if domain else None
