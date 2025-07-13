"""
JSON-based database service for Security Management Platform
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid
import logging
from .config import settings

logger = logging.getLogger(__name__)


class JSONDatabase:
    """Simple JSON-based data storage for development"""
    
    def __init__(self):
        self.data_dir = Path(settings.DATA_DIR)
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize data files
        self.collections = {
            "cves": self.data_dir / "cves.json",
            "vulnerabilities": self.data_dir / "vulnerabilities.json",
            "scan_results": self.data_dir / "scan_results.json",
            "patch_recommendations": self.data_dir / "patch_recommendations.json",
            "patch_deployments": self.data_dir / "patch_deployments.json",
            "threat_intelligence": self.data_dir / "threat_intelligence.json",
            "chat_sessions": self.data_dir / "chat_sessions.json",
            "chat_messages": self.data_dir / "chat_messages.json",
            "reports": self.data_dir / "reports.json",
            "assets": self.data_dir / "assets.json",
            "tickets": self.data_dir / "tickets.json",
            "risk_assessments": self.data_dir / "risk_assessments.json",
            "llm_interactions": self.data_dir / "llm_interactions.json",
            "github_advisories": self.data_dir / "github_advisories.json",
            "exploit_data": self.data_dir / "exploit_data.json",
            "nvd_data": self.data_dir / "nvd_data.json"
        }
        
        # Initialize empty files if they don't exist
        for collection_name, file_path in self.collections.items():
            if not file_path.exists():
                self._save_data(file_path, [])
                logger.info(f"Initialized empty collection: {collection_name}")
    
    def _load_data(self, file_path: Path) -> List[Dict[str, Any]]:
        """Load data from JSON file"""
        try:
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            return []
        except Exception as e:
            logger.error(f"Error loading data from {file_path}: {e}")
            return []
    
    def _save_data(self, file_path: Path, data: List[Dict[str, Any]]):
        """Save data to JSON file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving data to {file_path}: {e}")
    
    def get_all(self, collection: str) -> List[Dict[str, Any]]:
        """Get all records from a collection"""
        if collection not in self.collections:
            logger.warning(f"Unknown collection: {collection}")
            return []
        
        return self._load_data(self.collections[collection])
    
    def get_by_id(self, collection: str, record_id: str) -> Optional[Dict[str, Any]]:
        """Get a record by ID"""
        records = self.get_all(collection)
        for record in records:
            if record.get('id') == record_id:
                return record
        return None
    
    def create(self, collection: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new record"""
        if collection not in self.collections:
            raise ValueError(f"Unknown collection: {collection}")
        
        records = self.get_all(collection)
        
        # Generate ID if not provided
        if 'id' not in data:
            data['id'] = str(uuid.uuid4())
        
        # Add timestamps
        current_time = datetime.now().isoformat()
        data['created_at'] = current_time
        data['updated_at'] = current_time
        
        records.append(data)
        self._save_data(self.collections[collection], records)
        
        logger.info(f"Created record in {collection}: {data.get('id')}")
        return data
    
    def update(self, collection: str, record_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update a record"""
        if collection not in self.collections:
            raise ValueError(f"Unknown collection: {collection}")
        
        records = self.get_all(collection)
        
        for i, record in enumerate(records):
            if record.get('id') == record_id:
                # Update fields
                for key, value in data.items():
                    if key != 'id':  # Don't allow ID changes
                        record[key] = value
                
                record['updated_at'] = datetime.now().isoformat()
                self._save_data(self.collections[collection], records)
                
                logger.info(f"Updated record in {collection}: {record_id}")
                return record
        
        logger.warning(f"Record not found in {collection}: {record_id}")
        return None
    
    def delete(self, collection: str, record_id: str) -> bool:
        """Delete a record"""
        if collection not in self.collections:
            raise ValueError(f"Unknown collection: {collection}")
        
        records = self.get_all(collection)
        
        for i, record in enumerate(records):
            if record.get('id') == record_id:
                del records[i]
                self._save_data(self.collections[collection], records)
                logger.info(f"Deleted record from {collection}: {record_id}")
                return True
        
        logger.warning(f"Record not found for deletion in {collection}: {record_id}")
        return False
    
    def find(self, collection: str, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find records matching filters"""
        records = self.get_all(collection)
        results = []
        
        for record in records:
            match = True
            for key, value in filters.items():
                if key not in record:
                    match = False
                    break
                
                # Handle nested key access (e.g., "user.name")
                if '.' in key:
                    keys = key.split('.')
                    current = record
                    try:
                        for k in keys:
                            current = current[k]
                        if current != value:
                            match = False
                            break
                    except (KeyError, TypeError):
                        match = False
                        break
                else:
                    if record[key] != value:
                        match = False
                        break
            
            if match:
                results.append(record)
        
        return results
    
    def search(self, collection: str, query: str, fields: List[str] = None) -> List[Dict[str, Any]]:
        """Search records by text query in specified fields"""
        records = self.get_all(collection)
        results = []
        query_lower = query.lower()
        
        for record in records:
            match = False
            search_fields = fields or record.keys()
            
            for field in search_fields:
                if field in record:
                    field_value = str(record[field]).lower()
                    if query_lower in field_value:
                        match = True
                        break
            
            if match:
                results.append(record)
        
        return results
    
    def count(self, collection: str, filters: Dict[str, Any] = None) -> int:
        """Count records in collection with optional filters"""
        if filters:
            return len(self.find(collection, filters))
        return len(self.get_all(collection))
    
    def backup(self, backup_dir: str = None) -> str:
        """Create a backup of all data"""
        if backup_dir is None:
            backup_dir = self.data_dir / "backups"
        
        backup_path = Path(backup_dir)
        backup_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_path / f"backup_{timestamp}.json"
        
        all_data = {}
        for collection_name, file_path in self.collections.items():
            all_data[collection_name] = self._load_data(file_path)
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(all_data, f, indent=2, default=str, ensure_ascii=False)
        
        logger.info(f"Created backup: {backup_file}")
        return str(backup_file)
    
    def restore(self, backup_file: str) -> bool:
        """Restore data from backup file"""
        try:
            with open(backup_file, 'r', encoding='utf-8') as f:
                all_data = json.load(f)
            
            for collection_name, data in all_data.items():
                if collection_name in self.collections:
                    self._save_data(self.collections[collection_name], data)
            
            logger.info(f"Restored data from backup: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Error restoring backup {backup_file}: {e}")
            return False

    def clear_vulnerability_data(self) -> bool:
        """Clear all vulnerability-related data while preserving session data"""
        try:
            # Collections to clear (vulnerability data)
            vulnerability_collections = [
                "cves",
                "vulnerabilities", 
                "scan_results",
                "patch_recommendations",
                "patch_deployments",
                "threat_intelligence",
                "risk_assessments",
                "llm_interactions",
                "github_advisories",
                "exploit_data",
                "nvd_data"
            ]
            
            # Clear each vulnerability collection
            for collection in vulnerability_collections:
                if collection in self.collections:
                    self._save_data(self.collections[collection], [])
                    logger.info(f"Cleared vulnerability collection: {collection}")
            
            # Preserve session data (chat_sessions, chat_messages, reports, tickets, assets)
            session_collections = [
                "chat_sessions",
                "chat_messages", 
                "reports",
                "tickets"
            ]
            
            logger.info("Vulnerability data cleared. Session data preserved.")
            return True
            
        except Exception as e:
            logger.error(f"Error clearing vulnerability data: {e}")
            return False

    def clear_all_data(self) -> bool:
        """Clear all data from all collections"""
        try:
            for collection_name, file_path in self.collections.items():
                self._save_data(file_path, [])
                logger.info(f"Cleared collection: {collection_name}")
            
            logger.info("All data cleared successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error clearing all data: {e}")
            return False


# Global database instance
db = JSONDatabase()


# Convenience functions for common operations
def get_db() -> JSONDatabase:
    """Get database instance"""
    return db 