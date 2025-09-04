"""
Document Processor for CVSS Server
==================================

This module handles document uploads (Word, PDF) and extracts CVSS metrics
from the text content using natural language processing and pattern matching.
"""

import re
import io
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json

try:
    from docx import Document
    from PyPDF2 import PdfReader
    import pdfplumber
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    print("Warning: Document processing dependencies not available. Install with: pip install python-docx PyPDF2 pdfplumber")


class DocumentProcessor:
    """Processes uploaded documents to extract CVSS metrics."""
    
    def __init__(self):
        self.cvss_patterns = {
            # Attack Vector patterns - Más flexibles
            'AV': {
                'N': [r'\bnetwork\b', r'\bremote\b', r'\bover\s+network\b', r'\bnetwork\s+accessible\b', r'\bnetwork\s+based\b'],
                'A': [r'\badjacent\b', r'\bsame\s+network\b', r'\blocal\s+network\b', r'\bsubnet\b'],
                'L': [r'\blocal\b', r'\bon\s+system\b', r'\brequires\s+local\s+access\b', r'\blocal\s+access\b'],
                'P': [r'\bphysical\b', r'\bphysical\s+access\b', r'\brequires\s+physical\s+access\b']
            },
            # Attack Complexity patterns - Más flexibles
            'AC': {
                'L': [r'\blow\s+complexity\b', r'\bsimple\b', r'\beasy\b', r'\btrivial\b', r'\blow\b', r'\bsimple\s+to\s+exploit\b'],
                'H': [r'\bhigh\s+complexity\b', r'\bcomplex\b', r'\bdifficult\b', r'\brequires\s+special\b', r'\bhigh\b']
            },
            # Privileges Required patterns - Más flexibles
            'PR': {
                'N': [r'\bno\s+privileges\b', r'\bunprivileged\b', r'\bno\s+authentication\b', r'\bno\s+privileges\s+required\b', r'\bno\s+privileges\s+needed\b'],
                'L': [r'\blow\s+privileges\b', r'\bbasic\s+user\b', r'\buser\s+level\b', r'\blow\b'],
                'H': [r'\bhigh\s+privileges\b', r'\badmin\b', r'\broot\b', r'\belevated\b', r'\bhigh\b']
            },
            # User Interaction patterns - Más flexibles
            'UI': {
                'N': [r'\bno\s+user\s+interaction\b', r'\bautomatic\b', r'\bno\s+user\s+action\b', r'\bno\s+user\s+interaction\s+required\b', r'\bno\s+user\s+interaction\s+needed\b'],
                'R': [r'\brequires\s+user\s+interaction\b', r'\buser\s+must\s+click\b', r'\buser\s+action\b', r'\buser\s+interaction\s+required\b']
            },
            # Scope patterns - Más flexibles
            'S': {
                'U': [r'\bunchanged\s+scope\b', r'\bsame\s+component\b', r'\bwithin\s+component\b', r'\bunchanged\b', r'\bsame\s+component\b'],
                'C': [r'\bchanged\s+scope\b', r'\bdifferent\s+component\b', r'\bcross\s+component\b', r'\bchanged\b', r'\bdifferent\s+component\b']
            },
            # Impact patterns - Más flexibles
            'C': {
                'N': [r'\bno\s+confidentiality\s+impact\b', r'\bno\s+data\s+disclosure\b', r'\bno\s+impact\b', r'\bnone\b', r'\bno\s+data\s+leak\b'],
                'L': [r'\blow\s+confidentiality\s+impact\b', r'\bminor\s+data\s+leak\b', r'\blow\s+impact\b', r'\bminor\b'],
                'H': [r'\bhigh\s+confidentiality\s+impact\b', r'\bcomplete\s+data\s+disclosure\b', r'\bhigh\s+impact\b', r'\bcomplete\b', r'\bhigh\b']
            },
            'I': {
                'N': [r'\bno\s+integrity\s+impact\b', r'\bno\s+data\s+modification\b', r'\bno\s+impact\b', r'\bnone\b', r'\bno\s+data\s+modification\b'],
                'L': [r'\blow\s+integrity\s+impact\b', r'\bminor\s+data\s+modification\b', r'\blow\s+impact\b', r'\bminor\b'],
                'H': [r'\bhigh\s+integrity\s+impact\b', r'\bcomplete\s+data\s+modification\b', r'\bhigh\s+impact\b', r'\bcomplete\b', r'\bhigh\b']
            },
            'A': {
                'N': [r'\bno\s+availability\s+impact\b', r'\bno\s+service\s+disruption\b', r'\bno\s+availability\b', r'\bnone\b', r'\bno\s+service\s+disruption\b'],
                'L': [r'\blow\s+availability\s+impact\b', r'\bminor\s+service\s+disruption\b', r'\blow\s+availability\b', r'\bminor\b'],
                'H': [r'\bhigh\s+availability\s+impact\b', r'\bcomplete\s+service\s+disruption\b', r'\bhigh\s+availability\b', r'\bcomplete\b', r'\bhigh\b', r'\bhigh\s+availability\b']
            }
        }
    
    def extract_text_from_docx(self, file_content: bytes) -> str:
        """Extract text from Word document."""
        if not DEPENDENCIES_AVAILABLE:
            raise ImportError("python-docx not available")
        
        try:
            doc = Document(io.BytesIO(file_content))
            text = []
            for paragraph in doc.paragraphs:
                text.append(paragraph.text)
            return '\n'.join(text)
        except Exception as e:
            raise ValueError(f"Error reading Word document: {e}")
    
    def extract_text_from_pdf(self, file_content: bytes) -> str:
        """Extract text from PDF document."""
        if not DEPENDENCIES_AVAILABLE:
            raise ImportError("PyPDF2/pdfplumber not available")
        
        try:
            # Try pdfplumber first (better text extraction)
            with pdfplumber.open(io.BytesIO(file_content)) as pdf:
                text = []
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text.append(page_text)
                return '\n'.join(text)
        except Exception:
            try:
                # Fallback to PyPDF2
                reader = PdfReader(io.BytesIO(file_content))
                text = []
                for page in reader.pages:
                    text.append(page.extract_text())
                return '\n'.join(text)
            except Exception as e:
                raise ValueError(f"Error reading PDF document: {e}")
    
    def extract_text_from_file(self, file_content: bytes, filename: str) -> str:
        """Extract text from uploaded file based on file type."""
        filename_lower = filename.lower()
        
        if filename_lower.endswith('.docx'):
            return self.extract_text_from_docx(file_content)
        elif filename_lower.endswith('.pdf'):
            return self.extract_text_from_pdf(file_content)
        else:
            raise ValueError(f"Unsupported file type: {filename}")
    
    def detect_cvss_metrics(self, text: str) -> Dict[str, str]:
        """Detect CVSS metrics from text using pattern matching."""
        text_lower = text.lower()
        detected_metrics = {}
        
        # Debug: Print the text being analyzed
        print(f"🔍 DEBUG - Analyzing text: {text_lower[:300]}...")
        
        # Detect each metric with priority (H > L > N)
        for metric, values in self.cvss_patterns.items():
            detected = False
            
            # Check patterns in priority order: High first, then Low, then None
            priority_order = ['H', 'L', 'N'] if metric in ['C', 'I', 'A'] else ['N', 'A', 'L', 'P'] if metric == 'AV' else ['L', 'H'] if metric == 'AC' else ['N', 'L', 'H'] if metric == 'PR' else ['N', 'R'] if metric == 'UI' else ['U', 'C']
            
            for value in priority_order:
                if value in values:
                    patterns = values[value]
                    for pattern in patterns:
                        if re.search(pattern, text_lower, re.IGNORECASE):
                            detected_metrics[metric] = value
                            print(f"✅ {metric}: {value} (pattern: {pattern})")
                            detected = True
                            break
                    if detected:
                        break
            
            if not detected:
                print(f"❌ {metric}: No pattern matched")
        
        print(f"🔍 DEBUG - Final metrics: {detected_metrics}")
        return detected_metrics
    
    def extract_cve_id(self, text: str) -> Optional[str]:
        """Extract CVE ID from text."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        match = re.search(cve_pattern, text, re.IGNORECASE)
        return match.group() if match else None
    
    def extract_title(self, text: str) -> str:
        """Extract potential title from text."""
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if line and len(line) > 10 and len(line) < 200:
                # Skip common headers
                if not any(header in line.lower() for header in ['abstract', 'summary', 'introduction', 'description']):
                    return line[:200]  # Limit length
        return "Document Analysis"
    
    def process_document(self, file_content: bytes, filename: str) -> Dict[str, any]:
        """Process uploaded document and extract CVSS information."""
        try:
            # Extract text from document
            text = self.extract_text_from_file(file_content, filename)
            
            # Extract CVSS metrics
            metrics = self.detect_cvss_metrics(text)
            
            # Extract additional information
            cve_id = self.extract_cve_id(text)
            title = self.extract_title(text)
            
            return {
                'success': True,
                'text': text[:1000] + '...' if len(text) > 1000 else text,  # Truncate for display
                'metrics': metrics,
                'cve_id': cve_id,
                'title': title,
                'filename': filename
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'filename': filename
            }


# Global instance
document_processor = DocumentProcessor()
