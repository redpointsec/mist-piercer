import os
from langchain_aws import ChatBedrock
from langchain_aws import BedrockEmbeddings
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
#from langchain_ollama import OllamaLLM as Ollama

import base64
import xml.etree.ElementTree as ET

# Load Env Variables
from dotenv import load_dotenv
load_dotenv()

xml_file = 'test/vtm-session.xml'

xml = ET.parse(xml_file)
root = xml.getroot()
print(f"Parsing {len(root)} requests")

#llm = Ollama(model="deepseek-r1", temperature=0.2)

llm = ChatBedrock(
    model_id='qwen.qwen3-next-80b-a3b',
    model_kwargs={"temperature": 0.2},
)

embeddings = BedrockEmbeddings(model_id='amazon.titan-embed-text-v2:0')

system_prompt_template = """
You are a highly analytical agent specializing in both security and functional review. 
Your task is to analyze an HTTP Request and Response for possible user enumeration parameters and provide detailed insights through a multi-step reflection process.

### Analysis Process

1. Initial Analysis:
   - First, analyze the provided request thoroughly
   - Form initial observations about endpoint and any user-controlled parameters
   - Identify usernames or email addresses in the request

2. Reflection:
   - Critically evaluate your initial observations
   - Identify any potential gaps or assumptions in your analysis
   - Consider all possible user enumeration techniques
   - Think about how different portions of the HTTP Request could be used

3. Final Analysis:
   - Combine your initial analysis with your reflections
   - Prioritize your findings based on importance

Context for analysis:
{context}

Remember to:
- Identify areas where more investigation might be needed
- Only output the requested information, do not provide any additional details.

"""


prompt = ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt_template),
                ("human", """<question>{question}</question>""")
            ]
)

question = """"
Please analyze the following HTTP Request for possibility it could lead to user or email enumeration:

<content>
{content}
</content>

ONLY respond with the following information:
- URL: (str) The full URL of the request in the format: http://example.com/path
- HTTP Method: (str) The HTTP Method of the request
- Parameters: (str) The parameters of the request
- Possible User Enumeration: (str) Yes or No
- Possible Email Enumeration: (str) Yes or No
- Justification: (str) A brief justification ONLY if user or email enumeration is possible

DO NOT PROVIDE ADDITIONAL INFORMATION.
"""

chain = (
    { "context": RunnablePassthrough() , "question": RunnablePassthrough()}
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
    if item.find("request").attrib['base64'] == 'true':
        request = base64.b64decode(request).decode('utf-8')
    count = count+1

    try: 
        for chunk in chain.stream({"question": question, "content": request}):
            print(chunk, end="", flush=True)
            #response_array.append(chunk)
  

        print("\n=> Complete\n")
    except Exception as e:
        print(f"=> Error: {e}")

print("=" * 50)
