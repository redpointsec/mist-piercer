import os
from langchain_aws import ChatBedrock
from langchain_aws import BedrockEmbeddings
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS

import base64
import xml.etree.ElementTree as ET

# Load Env Variables
from dotenv import load_dotenv
load_dotenv()

xml_file = 'test/vtm-session.xml'

xml = ET.parse(xml_file)
root = xml.getroot()
print(f"Parsing {len(root)} requests")


#llm = Ollama(model="deepseek-r1", temperature=0.6)

llm = ChatBedrock(
    model_id='us.anthropic.claude-3-5-haiku-20241022-v1:0',
    model_kwargs={"temperature": 0.2},
)

embeddings = BedrockEmbeddings(model_id='amazon.titan-embed-text-v2:0')

system_prompt_template = """
You are a highly analytical information security agent specializing in both security and functional review. 
Your task is to analyze an HTTP Request and Response for possible vulnerabilities and provide detailed insights through a multi-step reflection process.

### Analysis Process

1. Initial Analysis:
   - First, analyze the provided request thoroughly
   - Form initial observations about endpoint and any parameters
   - Identify any unique identifiers in the request

2. Reflection:
   - Critically evaluate your initial observations
   - Identify any potential gaps or assumptions in your analysis
   - Consider possible user enumeration techniques
   - Think about how different portions of the HTTP Request are used

3. Final Analysis:
   - Combine your initial analysis with your reflections
   - Prioritize your findings based on importance

Context for analysis:
{context}

Remember to:
- Identify areas where more investigation might be needed

"""


prompt = ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt_template),
                ("human", """<question>{question}</question>""")
            ]
)

question = """"
Please analyze the following HTTP Request and Response for possibility it could lead to an authorization issue, either insecure direct object reference or missing authorization checks:

<content>
{context}
</content>

ONLY respond with the following information:
- URL: (str) The URL of the request
- HTTP Method: (str) The HTTP Method of the request
- Parameters: (str) The parameters of the request
- Possible Authorization Issue: (str) Yes or No
- Justification: (str) A brief justification for the authorization issue, including possible parameters or values that could be used to exploit the issue

Provide Justification ONLY IF the request and related response contains a possible authorization issue. 
DO NOT provide any other information.
"""

chain = (
    { 
        "context": RunnablePassthrough() , 
        "question": RunnablePassthrough()
    }
    | prompt
    | llm
    | StrOutputParser()
)

count = 1
urls = []
for item in root:
    print(f"=> {count}/{len(root)}: {item.find('url').text}")
    # Skip duplicate URLs, if needed
    #url = item.find('url').text
    #if url in urls:
    #    print("=> Duplicate URL, skipping")
    #    continue
    #urls.append(item.find('url').text)
    request = item.find("request").text
    response = item.find("response").text
    if item.find("request").attrib['base64'] == 'true':
        request = base64.b64decode(request).decode('utf-8')
    if item.find("response").attrib['base64'] == 'true':
        response = base64.b64decode(response).decode('utf-8')
    count = count+1

    try: 
        for chunk in chain.stream({"question": question, "context": request + "\n\n" + response}):
            print(chunk, end="", flush=True)
            #response_array.append(chunk)
  

        print("\n=> Complete\n")
    except Exception as e:
        print(f"=> Error: {e}")

print("=" * 50)
