#!/usr/bin/python
# Author : Saikiran Uppu
# Date Created : 2017-07-16

import time
from app import vtAPI
import json
from logger_class import Logger
import sys

class VT():
	
	def __init__( self ):
		self.logger = Logger(self.__class__.__name__).get()
		self.logger.info( 'Created VT info application' )	
	def search( self , hash ):
		"""
		This function searches VirusTotal
		and display whether sample is present
		in VT or not and also store the report in hash.json format
		If the hash is not available in vt, it returns none
		"""
		self.hash = hash
		self.logger.info('Hash User Requested : {}'.format(self.hash))
		vtAPI_obj = vtAPI()
		self.vt_report = vtAPI_obj.getReport( hash )
		#print self.vt_report
		self.logger.info('Report Generated for hash {} : {}'.format(self.hash , self.vt_report) )
		self.file_name = 'reports/{}.json'.format( hash )
		try:
			with open( self.file_name , 'w') as f:
				json.dump( self.vt_report , f)
		except Exception as e:
			self.logger.exception('Exception in downloading file {}'.format( str(e) ))	
	def threat_finder( self , hash ):
		"""
		This function extractes data for detection of AV's like 
		Sophos
		Kaspersky
		Fortinet
		TrendMicro
		Microsoft and calculate the real threat value
		"""
		self.av = {}
		
  	        if self.vt_report['response_code'] != 0:
			self.logger.info('File is found in VT : {}'.format( self.hash ) )
		
			self.sophos = self.vt_report['scans']['Sophos']['result']
			self.kaspersky = self.vt_report['scans']['Kaspersky']['result']
			self.fortinet = self.vt_report['scans']['Fortinet']['result']
			self.trendmicro = self.vt_report['scans']['TrendMicro']['result']	
			self.microsoft = self.vt_report['scans']['Microsoft']['result']
			

			'''
			print self.sophos
			print self.kaspersky
			print self.fortinet
			print self.trendmicro
			print self.microsoft
			'''	
			self.av['sophos'] 	= self.sophos
			self.av['kaspersky']    = self.kaspersky
			self.av['fortinet']     = self.fortinet
			self.av['trendmicro']   = self.trendmicro
			self.av['microsoft']    = self.microsoft

			print self.av
			"""
			Detection Logic choosen : Atleast 2 of all 5 engines
			"""
			self.flag = 0
			if self.vt_report['scans']['Sophos']['detected']:
				self.flag +=1
			if self.vt_report['scans']['Kaspersky']['detected']:
				self.flag +=1
                        if self.vt_report['scans']['Fortinet']['detected']:
				self.flag +=1
                        if self.vt_report['scans']['TrendMicro']['detected']:
				self.flag +=1
                        if self.vt_report['scans']['Microsoft']['detected']:
				self.flag +=1
			if self.flag >= 2 :
				print 'Potential Malware'

		else:
			self.logger.info('File is not found in VT : {}'.format( self.hash ) )
		
	def fp_detector( self , hash ):
		"""
		This function will detect the fp rate based on BD AV's
		"""
		self.av_names = []
	        if self.vt_report['response_code'] != 0:
			self.positives = self.vt_report['positives']
			#print self.vt_report['scans']
			for scan in self.vt_report['scans']:
				#print scan
				self.av_names.append(str(scan))
			#for av in self.av_names:
			#	print av , self.vt_report['scans'][av]['result'], self.vt_report['scans'][av]['detected']
			"""
			BitDefender AV's List
			Arcabit
			Emsisoft
			F-Secure	
			GData
			Ad-Aware	
			nProtect	
			Qihoo-360	
			"""
	                self.arcabit 	= self.vt_report['scans']['Arcabit']['detected']
                        self.emsisoft   = self.vt_report['scans']['Emsisoft']['detected']
                        self.fsecure 	= self.vt_report['scans']['F-Secure']['detected']
                        self.gdata 	= self.vt_report['scans']['GData']['detected']
                        self.adaware 	= self.vt_report['scans']['Ad-Aware']['detected']
                        self.nprotect 	= self.vt_report['scans']['nProtect']['detected']
                        self.qihoo 	= self.vt_report['scans']['Qihoo-360']['detected']
			#print self.arcabit,self.emsisoft,self.fsecure,self.gdata,self.adaware,self.nprotect,self.qihoo
			self.fp_count = 0
			if self.arcabit:
				self.fp_count +=1
			if self.emsisoft:
				self.fp_count +=1
			if self.fsecure:
				self.fp_count +=1
			if self.gdata:
				self.fp_count +=1
			if self.adaware:
				self.fp_count +=1
			if self.nprotect:
				self.fp_count +=1
			if self.qihoo:
				self.fp_count +=1
	
			
			if self.fp_count > 4:
				if self.positives < 11 and self.flag < 2:
					print 'Potential False Positive'
				else:
					pass
			else:
				pass
			
		else:
	                self.logger.info('File is not found in VT : {}'.format( self.hash ) )
	
def main():
	vt = VT()
	vt.search( sys.argv[1] )
	vt.threat_finder( sys.argv[1] )
	vt.fp_detector( sys.argv[1] )		
		
if __name__ == '__main__':
	main()
